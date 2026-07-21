//! `/xailogout` — full SpaceXAI logout and return to the login screen
//! (formerly bare `/logout` upstream).

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand};

pub struct XaiLogoutCommand;

impl SlashCommand for XaiLogoutCommand {
    fn name(&self) -> &str {
        "xailogout"
    }

    fn description(&self) -> &str {
        "Log out of SpaceXAI and return to the login screen"
    }

    fn usage(&self) -> &str {
        "/xailogout"
    }

    fn run(&self, _ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        CommandResult::Action(Action::Logout)
    }
}
