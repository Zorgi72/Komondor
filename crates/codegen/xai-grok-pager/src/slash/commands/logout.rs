//! `/logout` — remove Zyth gateway models/credentials only (fork default).
//!
//! Does **not** force the welcome screen. Full SpaceXAI session logout is
//! `/xailogout`. Legacy alias: `/logoutzyth`.

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand};

pub struct LogoutCommand;

impl SlashCommand for LogoutCommand {
    fn name(&self) -> &str {
        "logout"
    }

    fn description(&self) -> &str {
        "Remove Zyth models / gateway access (keeps CLI session + SpaceXAI login)"
    }

    fn usage(&self) -> &str {
        "/logout"
    }

    fn run(&self, _ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        CommandResult::Action(Action::LogoutZyth)
    }
}
