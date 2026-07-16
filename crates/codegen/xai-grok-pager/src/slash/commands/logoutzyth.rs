//! `/logoutzyth` — clear Zyth AuthStack / AI gateway credentials only.

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand};

pub struct LogoutZythCommand;

impl SlashCommand for LogoutZythCommand {
    fn name(&self) -> &str {
        "logoutzyth"
    }

    fn description(&self) -> &str {
        "Log out of Zyth SSO (keeps SpaceXAI /login session)"
    }

    fn usage(&self) -> &str {
        "/logoutzyth"
    }

    fn run(&self, _ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        CommandResult::Action(Action::LogoutZyth)
    }
}
