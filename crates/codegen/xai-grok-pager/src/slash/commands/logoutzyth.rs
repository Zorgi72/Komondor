//! `/logoutzyth` — remove Zyth gateway models and credentials only.
//!
//! Does **not** log out of the whole CLI or force the welcome screen. SpaceXAI
//! `/login` sessions stay intact; the session and TUI remain usable.

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand};

pub struct LogoutZythCommand;

impl SlashCommand for LogoutZythCommand {
    fn name(&self) -> &str {
        "logoutzyth"
    }

    fn description(&self) -> &str {
        "Remove Zyth models / gateway access (keeps CLI session + SpaceXAI login)"
    }

    fn usage(&self) -> &str {
        "/logoutzyth"
    }

    fn run(&self, _ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        CommandResult::Action(Action::LogoutZyth)
    }
}
