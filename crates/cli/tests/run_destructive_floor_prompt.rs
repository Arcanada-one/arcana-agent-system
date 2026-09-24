//! A2-234: the model is told, before it acts, which commands the destructive
//! floor refuses and what to use instead.
//!
//! Measured on pilot A2-231 (`/home/dev/aup/arc2/runs/A2-231/log`, `arcana`
//! 0.2.0, sha256 `2830536b…`, 2026-09-23): 78 turns, 62 tool calls, 0.27 USD,
//! and the run ended here —
//!
//! ```text
//! arcana run: the permission cascade refused the tool call (PermissionDenied):
//! destructive_command_floor layer refused `bash`: refused: `rm` with recursive
//! and force flags — deletes trees irrecoverably
//! ```
//!
//! The floor was right. The model was not evading it: it wanted to clear its
//! own scratch directory, and `rm -r` without `-f` — which the floor permits —
//! would have done exactly that. The system prompt's only word on the subject
//! was the clause "recursive force deletion … refused by policy", which names
//! no command, states no alternative, and cannot be checked against.
//!
//! Three things are pinned here, and the middle one is the load-bearing one:
//!
//! 1. the prompt NAMES every entry of the floor's closed lists, so a command
//!    added to the floor cannot start refusing runs silently;
//! 2. what the prompt STATES about a command equals what the floor actually
//!    DOES to it — the disclosure is measured against
//!    [`WorkspacePolicy::assess`], not against anybody's memory of it;
//! 3. a model that reads the prompt and applies what it says picks a command
//!    the floor allows, where the same model against the old prompt picks
//!    `rm -rf` and loses the run.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use arcana_cli::run::{assemble, driver_config, system_prompt, RunRequest};
use arcana_cli::workspace::{
    destructive_floor_disclosure, refused_command_phrases, refused_command_words, Assessment,
    WorkspacePolicy,
};
use arcana_core::agent_loop::{RunOutput, TerminalReason};
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use async_trait::async_trait;
use serde_json::json;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// 1 + 2 — the disclosure is complete, and it is accurate
// ---------------------------------------------------------------------------

#[test]
fn the_prompt_names_every_command_the_floor_refuses() {
    let root = TempDir::new().unwrap();
    let prompt = prompt_for(root.path());

    for word in refused_command_words() {
        assert!(
            prompt.contains(word),
            "the floor refuses `{word}` and the prompt never says so"
        );
    }
    for phrase in refused_command_phrases() {
        assert!(
            prompt.contains(&phrase),
            "the floor refuses `{phrase}` and the prompt never says so"
        );
    }
}

/// The disclosure is only worth having if it is TRUE. Each row is a real
/// command; the prompt's own words are parsed back out (by
/// [`PromptFloorRules`], the same parse the test model below uses) and
/// compared against the floor's verdict on that command.
///
/// A row where the two disagree is either a prompt that forbids what the
/// runner allows — which costs the model capability it has — or a prompt that
/// permits what the runner refuses, which is the A2-231 failure again with
/// extra steps.
#[test]
fn what_the_prompt_says_about_a_command_is_what_the_floor_does_to_it() {
    let root = TempDir::new().unwrap();
    let policy = WorkspacePolicy::new(root.path()).unwrap();
    let rules = PromptFloorRules::parse(&prompt_for(root.path()));

    let commands = [
        // The pilot's command, and the alternatives around it.
        "rm -rf scratch",
        "rm -fr scratch",
        "rm -r --force scratch",
        "rm -r scratch",
        "rm -f note.txt",
        "rm note.txt",
        "mkdir scratch2",
        // Named outright.
        "sudo apt-get install ripgrep",
        "chmod 777 notes.txt",
        "systemctl restart nginx",
        "kill 1234",
        "ssh build-host uptime",
        "dd if=/dev/zero of=disk.img",
        // Phrases: the leading word alone is not the rule.
        "git clean -fd",
        "git reset --hard HEAD~1",
        "git push --force origin main",
        "git stash push -m wip",
        "git push origin HEAD",
        // A2-259: the `git stash` rule is decided by the SUBCOMMAND, and the
        // prompt has to carry the split or a model reading it loses the two
        // forms that only read the stack — which is how pilot A2-240d died
        // with its work finished.
        "git stash",
        "git stash pop",
        "git stash drop",
        "git stash clear",
        "git --no-pager stash drop",
        "git stash list",
        "git stash show",
        "git stash show stash@{0}",
        "git commit -m 'work'",
        "git add -A",
        // Plainly fine.
        "cargo test --offline",
        "grep -rn TODO src",
        "mv a.txt b.txt",
        "cp -r src src.bak",
        "find . -name '*.rs'",
    ];

    for command in commands {
        let floor_refuses = matches!(
            policy.assess("bash", &json!({ "command": command })),
            Assessment::Destructive(_)
        );
        assert_eq!(
            rules.refuses(command),
            floor_refuses,
            "the prompt and the floor disagree about `{command}`: the prompt says \
             refused={}, the floor says refused={floor_refuses}",
            rules.refuses(command)
        );
    }
}

/// The disclosure must state the recovery, not only the refusal. A model told
/// "`rm -rf` is refused" and nothing else has no reason to believe `rm -r`
/// works, and the pilot had nothing else to go on.
#[test]
fn the_prompt_names_the_permitted_alternative_and_the_cost_of_ignoring_it() {
    let disclosure = destructive_floor_disclosure();
    assert!(
        disclosure.contains("`rm -r <dir>`") && disclosure.contains("PERMITTED"),
        "no permitted alternative to `rm -rf`: {disclosure}"
    );
    assert!(
        disclosure.contains("ENDS THE RUN"),
        "a floor refusal is terminal and the prompt must say so: {disclosure}"
    );
}

// ---------------------------------------------------------------------------
// 3 — a model that reads the prompt survives; the same model without it dies
// ---------------------------------------------------------------------------

/// The pilot's intent, replayed: empty a scratch directory, preferring the
/// spelling models reach for first.
const CANDIDATES: [&str; 2] = ["rm -rf scratch", "rm -r scratch"];

#[tokio::test]
async fn a_model_that_reads_the_prompt_clears_its_scratch_dir_without_losing_the_run() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    make_scratch(work.path());

    let model = FloorReadingModel::new();
    let out = drive(work.path(), audit.path(), model.clone()).await;

    // The directory first: the verdict is what the run SAYS, and what matters
    // is what it DID.
    assert!(
        !work.path().join("scratch").exists(),
        "the scratch directory survived: the run never cleared it ({:?})",
        out.reason
    );
    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "the run did not survive its own cleanup: {:?}",
        out.terminal_detail
    );
    assert_eq!(
        model.chosen(),
        Some("rm -r scratch".to_owned()),
        "the model did not act on what the prompt told it"
    );
}

/// The red half, and it is the pilot. The same model, the same goal, the same
/// tools — only the prompt is the pre-A2-234 one, whose sole word on the
/// subject is the clause quoted below. It reaches for `rm -rf`, the floor
/// refuses, and 78 turns of work would go with it.
///
/// Without this the test above proves nothing: a check that cannot go red is
/// not a check.
#[tokio::test]
async fn the_same_model_without_the_disclosure_reaches_for_rm_rf_and_loses_the_run() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    make_scratch(work.path());

    let model = FloorReadingModel::new();
    let out = drive_with_prompt(
        work.path(),
        audit.path(),
        model.clone(),
        Some(OLD_PROMPT_CLAUSE.to_owned()),
    )
    .await;

    assert_eq!(
        model.chosen(),
        Some("rm -rf scratch".to_owned()),
        "the model was supposed to pick the refused spelling here"
    );
    assert_eq!(
        out.reason,
        TerminalReason::PermissionDenied,
        "the floor was supposed to end this run"
    );
    let detail = out.terminal_detail.unwrap_or_default();
    assert!(
        detail.contains("destructive_command_floor"),
        "not the pilot's failure: {detail}"
    );
    assert!(
        work.path().join("scratch").exists(),
        "nothing should have been deleted"
    );
}

/// The whole of what the pre-A2-234 prompt said about the floor, quoted from
/// `crates/cli/src/run.rs` as it stood at `79514da`.
const OLD_PROMPT_CLAUSE: &str = "WORKSPACE BOUNDARY. Every path you touch must be inside the \
working directory; prefer relative paths. Shell commands run there. Destructive commands \
(privilege escalation, package or service management, recursive force deletion, history \
rewriting) are refused by policy and end the run — do not retry one, say what was refused \
instead.";

// ---------------------------------------------------------------------------
// The model under test
// ---------------------------------------------------------------------------

/// What a reader can recover from the prompt's refusal section.
///
/// Deliberately generic: it learns the closed name list and the multi-word
/// command forms the section quotes, and applies them to a candidate. It does
/// NOT know that `rm` is special, that `-f` is the problem, or which answer
/// the test wants — feed it a prompt that names nothing and it refuses
/// nothing, which is why the red half above works at all.
struct PromptFloorRules {
    /// Command words named as refused outright.
    names: Vec<String>,
    /// Multi-word command forms quoted as refused, e.g. `git push --force`,
    /// `rm -rf`. A candidate that starts with one of these, on a word
    /// boundary, is refused.
    forms: Vec<String>,
    /// Multi-word command forms quoted in the "use these instead" half as
    /// permitted, e.g. `git stash list`, `git commit`.
    ///
    /// A second list is needed because the prompt states a rule and then an
    /// exception to it, and both are true: `git stash` is refused, `git stash
    /// list` is not. The two are reconciled by [`Self::refuses`] the way a
    /// reader reconciles them — the more specific sentence wins.
    permitted: Vec<String>,
}

impl PromptFloorRules {
    /// Read the refusal section — everything from the section heading up to
    /// the sentence that starts listing what to use instead.
    fn parse(prompt: &str) -> Self {
        let section = match prompt.find("DESTRUCTIVE COMMANDS.") {
            Some(start) => {
                let rest = &prompt[start..];
                let end = rest.find("Use these instead").unwrap_or(rest.len());
                &rest[..end]
            }
            None => "",
        };

        let names = section
            .lines()
            .find_map(|line| line.split_once("Refused by name"))
            .and_then(|(_, tail)| tail.split_once(": "))
            .map(|(_, list)| {
                list.trim_end_matches('.')
                    .split(',')
                    .map(|word| word.trim().trim_matches('`').to_owned())
                    .filter(|word| !word.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        // Every backquoted run in the section that is itself a command line
        // (more than one word) — the phrase list and the shape examples both
        // arrive this way, and neither needs its own parser.
        let forms = quoted_command_forms(section);

        // The other half of the same block: what it says to use instead,
        // read the same way.
        let instead = match prompt.find("Use these instead") {
            Some(start) => {
                let rest = &prompt[start..];
                let end = rest.find("REFUSED CALLS").unwrap_or(rest.len());
                &rest[..end]
            }
            None => "",
        };
        let permitted = quoted_command_forms(instead);

        Self {
            names,
            forms,
            permitted,
        }
    }

    /// Does the prompt, as parsed, say this command is refused?
    ///
    /// The longer statement wins, which is the only rule that reads both
    /// halves without knowing what any particular command means: `git stash
    /// list` beats `git stash` (permitted), `git push --force` beats `git
    /// push` (refused).
    fn refuses(&self, command: &str) -> bool {
        let head = command.split_whitespace().next().unwrap_or_default();
        if self.names.iter().any(|name| name == head) {
            return true;
        }
        longest_match(&self.forms, command) > longest_match(&self.permitted, command)
    }
}

/// Every backquoted run in `section` that is itself a command line (more than
/// one word). The phrase list, the shape examples and the permitted forms all
/// arrive this way, and none of them needs its own parser.
fn quoted_command_forms(section: &str) -> Vec<String> {
    section
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|quoted| quoted.contains(' '))
        .map(str::to_owned)
        .collect()
}

/// Words in the longest entry of `forms` that `command` starts with, on a word
/// boundary; 0 when none matches.
fn longest_match(forms: &[String], command: &str) -> usize {
    forms
        .iter()
        .filter(|form| {
            command == form.as_str()
                || command
                    .strip_prefix(form.as_str())
                    .is_some_and(|rest| rest.starts_with(' '))
        })
        .map(|form| form.split_whitespace().count())
        .max()
        .unwrap_or(0)
}

/// A model with one goal — clear `scratch/` — that consults the prompt before
/// choosing how to spell it, and reports what it chose.
#[derive(Clone)]
struct FloorReadingModel {
    turn: Arc<AtomicUsize>,
    chosen: Arc<Mutex<Option<String>>>,
}

impl FloorReadingModel {
    fn new() -> Self {
        Self {
            turn: Arc::new(AtomicUsize::new(0)),
            chosen: Arc::new(Mutex::new(None)),
        }
    }

    fn chosen(&self) -> Option<String> {
        self.chosen.lock().unwrap().clone()
    }
}

#[async_trait]
impl ModelConnector for FloorReadingModel {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let index = self.turn.fetch_add(1, Ordering::SeqCst);
        let result = if index == 0 {
            let rules = PromptFloorRules::parse(req.system_prompt.as_deref().unwrap_or_default());
            // First candidate the prompt does not name as refused. A prompt
            // that says nothing leaves the first one standing — which is the
            // pilot.
            let command = CANDIDATES
                .iter()
                .find(|candidate| !rules.refuses(candidate))
                .map_or(CANDIDATES[0], |candidate| *candidate);
            *self.chosen.lock().unwrap() = Some(command.to_owned());
            format!(
                "```tool_call\n{}\n```",
                json!({ "name": "bash", "input": { "command": command } })
            )
        } else {
            "cleared the scratch directory".to_owned()
        };
        Ok(ConnectorResponse {
            id: format!("floor-reader-{index}"),
            connector: "scripted".to_owned(),
            model: "scripted-model".to_owned(),
            result,
            usage: Usage {
                input_tokens: 1,
                output_tokens: 1,
                total_tokens: 2,
                cost_usd: 0.0,
            },
            latency_ms: 0,
            status: "success".to_owned(),
            error: None,
            first_dispatch_observation: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn prompt_for(root: &Path) -> String {
    let policy = Arc::new(WorkspacePolicy::new(root).unwrap());
    let audit = TempDir::new().unwrap();
    let workspace = assemble(
        root,
        &policy,
        Box::new(FloorReadingModel::new()),
        audit.path().to_path_buf(),
    )
    .expect("compose the headless run");
    system_prompt(&workspace.tools, root)
}

fn make_scratch(root: &Path) {
    let scratch = root.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(scratch.join("junk.txt"), "junk").unwrap();
}

async fn drive(root: &Path, audit: &Path, model: FloorReadingModel) -> RunOutput {
    drive_with_prompt(root, audit, model, None).await
}

/// Drive one run. `prompt_override` replaces the composed system prompt, which
/// is how the pre-A2-234 prompt is put back in front of the same model.
async fn drive_with_prompt(
    root: &Path,
    audit: &Path,
    model: FloorReadingModel,
    prompt_override: Option<String>,
) -> RunOutput {
    let policy = Arc::new(WorkspacePolicy::new(root).unwrap());
    let workspace = assemble(root, &policy, Box::new(model), audit.to_path_buf())
        .expect("compose the headless run");
    let request = RunRequest {
        cwd: root.to_path_buf(),
        prompt: "clear the scratch directory".to_owned(),
        max_turns: 6,
        max_cost_usd: None,
        model: Some("scripted-model".to_owned()),
        request_timeout: None,
        context_budget: None,
        tool_result_budget: None,
        save_transcript: None,
    };
    let mut config = driver_config(&request, &workspace.tools, root);
    if let Some(prompt) = prompt_override {
        config.system_prompt = Some(prompt);
    }
    workspace
        .session
        .run_task(&request.prompt, config, CancellationToken::new())
        .await
}
