import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CdpSession } from "./cdp.js";
import { createServer } from "./server.js";

async function main(): Promise<void> {
  const session = new CdpSession();
  const server = createServer(session);
  const transport = new StdioServerTransport();

  process.once("SIGINT", async () => {
    await session.disconnect();
    await server.close();
    process.exit(0);
  });
  process.once("SIGTERM", async () => {
    await session.disconnect();
    await server.close();
    process.exit(0);
  });

  await server.connect(transport);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
