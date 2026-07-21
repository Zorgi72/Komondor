//! `/xailogin` — SpaceXAI OAuth login (formerly bare `/login` upstream).

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand};

pub struct XaiLoginCommand;

impl SlashCommand for XaiLoginCommand {
    fn name(&self) -> &str {
        "xailogin"
    }

    fn description(&self) -> &str {
        "Log in or re-authenticate with SpaceXAI (auth.x.ai)"
    }

    fn usage(&self) -> &str {
        "/xailogin"
    }

    fn run(&self, _ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        CommandResult::Action(Action::Login)
    }
}
