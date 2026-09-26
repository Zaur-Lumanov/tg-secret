/**
 * Minimal client for https://my.telegram.org — the web panel where api_id/api_hash live.
 * Login: phone -> confirmation code delivered to the Telegram app (not SMS) -> stel_token cookie.
 */

const BASE = "https://my.telegram.org";

export interface ApiCredentials {
  apiId: number;
  apiHash: string;
}

export interface NewAppInfo {
  title: string;
  shortName: string;
  platform?: "desktop" | "android" | "ios" | "web" | "other";
  url?: string;
  description?: string;
}

export class MyTelegramOrgError extends Error {}

export class MyTelegramOrg {
  private phone = "";
  private randomHash = "";
  private cookie = "";

  private async post(path: string, form: Record<string, string>): Promise<Response> {
    return fetch(BASE + path, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        Origin: BASE,
        Referer: BASE + "/auth",
        ...(this.cookie ? { Cookie: this.cookie } : {}),
      },
      body: new URLSearchParams(form).toString(),
      redirect: "manual",
    });
  }

  /** Requests a confirmation code; it arrives as a message from "Telegram" in the app. */
  async sendCode(phone: string): Promise<void> {
    this.phone = phone;
    const res = await this.post("/auth/send_password", { phone });
    const text = await res.text();
    let data: { random_hash?: string };
    try {
      data = JSON.parse(text) as { random_hash?: string };
    } catch {
      throw new MyTelegramOrgError(text.trim() || `HTTP ${res.status}`);
    }
    if (!data.random_hash) throw new MyTelegramOrgError(`Unexpected response: ${text}`);
    this.randomHash = data.random_hash;
  }

  async login(code: string): Promise<void> {
    const res = await this.post("/auth/login", {
      phone: this.phone,
      random_hash: this.randomHash,
      password: code,
    });
    const text = (await res.text()).trim();
    const token = res.headers
      .getSetCookie()
      .map((c) => c.split(";")[0])
      .find((c) => c.startsWith("stel_token="));
    if (text !== "true" || !token) throw new MyTelegramOrgError(text || "Sign-in failed");
    this.cookie = token;
  }

  private async appsPage(): Promise<string> {
    const res = await fetch(BASE + "/apps", { headers: { Cookie: this.cookie }, redirect: "manual" });
    if (res.status !== 200) throw new MyTelegramOrgError(`Could not open /apps (HTTP ${res.status})`);
    return res.text();
  }

  /** Returns existing credentials, or undefined if the account has no application yet. */
  async getCredentials(): Promise<ApiCredentials | undefined> {
    return parseCredentials(await this.appsPage());
  }

  async createApp(app: NewAppInfo): Promise<ApiCredentials> {
    const page = await this.appsPage();
    const existing = parseCredentials(page);
    if (existing) return existing;

    const hash = /name="hash"\s+value="([^"]+)"/.exec(page)?.[1];
    if (!hash) throw new MyTelegramOrgError("App creation form not found on /apps");

    const res = await this.post("/apps/create", {
      hash,
      app_title: app.title,
      app_shortname: app.shortName,
      app_url: app.url ?? "",
      app_platform: app.platform ?? "desktop",
      app_desc: app.description ?? "",
    });
    const text = (await res.text()).trim();
    if (text && text !== "true" && !text.startsWith("<")) {
      throw new MyTelegramOrgError(`Telegram rejected app creation: ${text}`);
    }
    const created = await this.getCredentials();
    if (!created) {
      throw new MyTelegramOrgError(
        "The app was not created (Telegram often answers ERROR for new accounts, VPNs or proxies). " +
          "Try another title or create it manually at https://my.telegram.org/apps",
      );
    }
    return created;
  }

  async logout(): Promise<void> {
    if (!this.cookie) return;
    await fetch(BASE + "/auth/logout", { headers: { Cookie: this.cookie }, redirect: "manual" }).catch(() => undefined);
    this.cookie = "";
  }
}

export function parseCredentials(html: string): ApiCredentials | undefined {
  const id = /api_id[\s\S]{0,400}?<strong>\s*(\d+)\s*<\/strong>/.exec(html)?.[1];
  const hash = /api_hash[\s\S]{0,400}?>\s*([0-9a-f]{32})\s*</.exec(html)?.[1];
  return id && hash ? { apiId: Number(id), apiHash: hash } : undefined;
}
