//! `/logoutzyth` — legacy alias for default `/logout` (Zyth-only credential clear).

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand};

pub struct LogoutZythCommand;

impl SlashCommand for LogoutZythCommand {
    fn name(&self) -> &str {
        "logoutzyth"
    }

    fn description(&self) -> &str {
        "Alias for /logout — remove Zyth models/gateway only"
    }

    fn usage(&self) -> &str {
        "/logoutzyth"
    }

    fn run(&self, _ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        CommandResult::Action(Action::LogoutZyth)
    }
}
