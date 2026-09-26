import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizePhone } from "../src/account.js";
import { parseCredentials } from "../src/auth/myTelegramOrg.js";

test("normalizePhone keeps digits only and validates length", () => {
  assert.equal(normalizePhone("+7 (999) 123-45-67"), "79991234567");
  assert.equal(normalizePhone("79991234567"), "79991234567");
  assert.throws(() => normalizePhone("12"));
});

test("parseCredentials extracts api_id/api_hash from the my.telegram.org apps page", () => {
  const html = `
    <div class="form-group">
      <label for="app_id" class="col-md-4 text-right control-label">App api_id:</label>
      <div class="col-md-7">
        <span class="form-control input-xlarge uneditable-input" onclick="this.select();"><strong>1234567</strong></span>
      </div>
    </div>
    <div class="form-group">
      <label for="app_hash" class="col-md-4 text-right control-label">App api_hash:</label>
      <div class="col-md-7">
        <span class="form-control input-xlarge uneditable-input" onclick="this.select();">0123456789abcdef0123456789abcdef</span>
      </div>
    </div>`;
  assert.deepEqual(parseCredentials(html), { apiId: 1234567, apiHash: "0123456789abcdef0123456789abcdef" });
  assert.equal(parseCredentials('<form><input type="hidden" name="hash" value="x"/></form>'), undefined);
});
