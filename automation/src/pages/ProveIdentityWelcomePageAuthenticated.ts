import { IpvIdentityStartPage } from "./IpvIdentityStartPage";
import { GovUkOneLoginPageBase } from "./GovUkOneLoginPageBase";

export class ProveIdentityWelcomeAuthenticatedPage extends GovUkOneLoginPageBase {
  async continueToSignInOrCreateAccount(): Promise<IpvIdentityStartPage> {
    await this.clickOn("input[name='chooseWayPyi'][value='continue']");
    await this.clickOn("button[type='Submit']");
    return new IpvIdentityStartPage(this.driver);
  }
  async proveIdentityAnotherWay(): Promise<void> {
    await this.clickOn("input[name='chooseWayPyi'][value='redirect']");
    await this.clickOn("button[type='Submit']");
  }
}
