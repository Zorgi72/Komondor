//! `/login` — sign in with Zyth AuthStack SSO (fork default).
//!
//! SpaceXAI OAuth is `/xailogin`. Legacy alias: `/loginzyth`.

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand};

pub struct LoginCommand;

impl SlashCommand for LoginCommand {
    fn name(&self) -> &str {
        "login"
    }

    fn description(&self) -> &str {
        "Sign in with Zyth SSO (AuthStack) and use the Zyth AI gateway"
    }

    fn usage(&self) -> &str {
        "/login"
    }

    fn run(&self, _ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        CommandResult::Action(Action::LoginZyth)
    }
}
