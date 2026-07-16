//! `/loginzyth` — sign in with Zyth AuthStack SSO and use the Zyth AI gateway.

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand};

pub struct LoginZythCommand;

impl SlashCommand for LoginZythCommand {
    fn name(&self) -> &str {
        "loginzyth"
    }

    fn description(&self) -> &str {
        "Sign in with Zyth SSO (AuthStack) and use the Zyth AI gateway"
    }

    fn usage(&self) -> &str {
        "/loginzyth"
    }

    fn run(&self, _ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        CommandResult::Action(Action::LoginZyth)
    }
}
