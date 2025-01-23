import { cookies } from "next/headers";

export default function Home() {
  const credentials = JSON.parse(cookies().get("credentials")?.value || "{}");
  console.log({ credentials });
  const accessToken = credentials?.access_token;
  return (
    <div>
      <a href="/auth/samsara">Connect to Samsara</a>
      <p>Access Token: {accessToken}</p>
      <a href="/me">Test API Call</a>
      <br />
      <a href="/auth/samsara/refresh">Refresh Access Token</a>
      <br />
      <a href="/auth/samsara/revoke">Revoke Access Token</a>
      <br />
    </div>
  );
}
