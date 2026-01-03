#!/usr/bin/env node
/**
 * Tenant MCP Server
 *
 * Exposes Tenant functionality to AI assistants via the Model Context Protocol.
 * Enables creating, searching, and managing Things from Claude and other MCP clients.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import {
  TenantClient,
  CreateThingRequest,
  UpdateThingRequest,
} from "./client.js";

// ============================================================
// CONFIGURATION
// ============================================================

const TENANT_URL = process.env.TENANT_URL || "http://localhost:8069";
const TENANT_API_KEY = process.env.TENANT_API_KEY;

if (!TENANT_API_KEY) {
  console.error("Error: TENANT_API_KEY environment variable is required");
  process.exit(1);
}

const client = new TenantClient({
  baseUrl: TENANT_URL,
  apiKey: TENANT_API_KEY,
});

// ============================================================
// SERVER SETUP
// ============================================================

const server = new Server(
  {
    name: "tenant-mcp",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
      resources: {},
    },
  }
);

// ============================================================
// TOOLS
// ============================================================

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "tenant_create_thing",
      description:
        "Create a new Thing in Tenant. Things can be notes, links, tasks, photos, or any custom Kind. Use this to save information, create tasks, or capture ideas from the conversation.",
      inputSchema: {
        type: "object" as const,
        properties: {
          content: {
            type: "string",
            description: "The main text content of the Thing",
          },
          type: {
            type: "string",
            description:
              "The Kind of Thing to create. Common types: 'note' (default), 'link', 'task', 'post'. Use 'link' for URLs, 'task' for to-dos.",
            default: "note",
          },
          visibility: {
            type: "string",
            enum: ["private", "friends", "public"],
            description:
              "Who can see this Thing. Default is 'private'. Use 'public' only if explicitly requested.",
            default: "private",
          },
          metadata: {
            type: "object",
            description:
              "Additional attributes for the Thing. For 'link' type, include { url: '...' }. For 'task' type, include { done: false }.",
          },
        },
        required: ["content"],
      },
    },
    {
      name: "tenant_search",
      description:
        "Search for Things in Tenant. Use this to find relevant context, look up previous notes, or check what the user has saved about a topic.",
      inputSchema: {
        type: "object" as const,
        properties: {
          query: {
            type: "string",
            description: "Search query - searches content and metadata",
          },
          kind: {
            type: "string",
            description:
              "Filter by Kind (e.g., 'note', 'link', 'task'). Leave empty to search all.",
          },
          tag: {
            type: "string",
            description: "Filter by tag name",
          },
          limit: {
            type: "number",
            description: "Maximum number of results to return (default: 20)",
            default: 20,
          },
        },
        required: ["query"],
      },
    },
    {
      name: "tenant_get_thing",
      description:
        "Get a specific Thing by ID. Use this to retrieve full details of a Thing found via search.",
      inputSchema: {
        type: "object" as const,
        properties: {
          id: {
            type: "string",
            description: "The ID of the Thing to retrieve",
          },
        },
        required: ["id"],
      },
    },
    {
      name: "tenant_update_thing",
      description:
        "Update an existing Thing. Use this to modify content, change visibility, mark tasks as done, or add metadata.",
      inputSchema: {
        type: "object" as const,
        properties: {
          id: {
            type: "string",
            description: "The ID of the Thing to update",
          },
          content: {
            type: "string",
            description: "New content (replaces existing)",
          },
          visibility: {
            type: "string",
            enum: ["private", "friends", "public"],
            description: "New visibility setting",
          },
          metadata: {
            type: "object",
            description:
              "Updated metadata. For tasks, use { done: true } to mark complete.",
          },
        },
        required: ["id"],
      },
    },
    {
      name: "tenant_delete_thing",
      description:
        "Delete a Thing. Use with caution - only delete when explicitly requested by the user.",
      inputSchema: {
        type: "object" as const,
        properties: {
          id: {
            type: "string",
            description: "The ID of the Thing to delete",
          },
        },
        required: ["id"],
      },
    },
    {
      name: "tenant_list_recent",
      description:
        "List recent Things. Use this to see what the user has been working on or to get context about recent activity.",
      inputSchema: {
        type: "object" as const,
        properties: {
          kind: {
            type: "string",
            description: "Filter by Kind (optional)",
          },
          limit: {
            type: "number",
            description: "Number of Things to return (default: 10)",
            default: 10,
          },
        },
      },
    },
    {
      name: "tenant_add_tag",
      description:
        "Add a tag to a Thing. Tags help organize and find Things later.",
      inputSchema: {
        type: "object" as const,
        properties: {
          thing_id: {
            type: "string",
            description: "The ID of the Thing to tag",
          },
          tag: {
            type: "string",
            description:
              "The tag name to add (without # prefix). Will be created if new.",
          },
        },
        required: ["thing_id", "tag"],
      },
    },
    {
      name: "tenant_list_kinds",
      description:
        "List available Kinds (types of Things). Use this to understand what types of content the user has configured.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "tenant_list_tags",
      description:
        "List all tags. Use this to see how the user organizes their Things.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "tenant_create_link",
      description:
        "Create a relationship between two Things. Use this to connect related content, like linking a task to its reference note.",
      inputSchema: {
        type: "object" as const,
        properties: {
          from_id: {
            type: "string",
            description: "The ID of the source Thing",
          },
          to_id: {
            type: "string",
            description: "The ID of the target Thing",
          },
          type: {
            type: "string",
            description:
              "The relationship type (default: 'links_to'). Other options: 'references', 'related_to'",
            default: "links_to",
          },
        },
        required: ["from_id", "to_id"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "tenant_create_thing": {
        const data: CreateThingRequest = {
          type: (args?.type as string) || "note",
          content: args?.content as string,
          visibility:
            (args?.visibility as "private" | "friends" | "public") || "private",
          metadata: (args?.metadata as Record<string, unknown>) || {},
        };
        const result = await client.createThing(data);
        if (result.success && result.data) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Created ${data.type} with ID: ${result.data.id}\n\nContent: ${result.data.content}\nVisibility: ${result.data.visibility}`,
              },
            ],
          };
        }
        throw new Error(result.error || "Failed to create Thing");
      }

      case "tenant_search": {
        const result = await client.searchThings(
          args?.query as string,
          (args?.limit as number) || 20
        );
        const things = result.items;
        if (things.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: `No Things found matching "${args?.query}"`,
              },
            ],
          };
        }
        const formatted = things
          .map(
            (t) =>
              `- [${t.type}] ${t.id.slice(0, 8)}...: ${t.content.slice(0, 100)}${t.content.length > 100 ? "..." : ""}`
          )
          .join("\n");
        return {
          content: [
            {
              type: "text" as const,
              text: `Found ${things.length} Things:\n\n${formatted}`,
            },
          ],
        };
      }

      case "tenant_get_thing": {
        const result = await client.getThing(args?.id as string);
        if (result.success && result.data) {
          const t = result.data;
          return {
            content: [
              {
                type: "text" as const,
                text: `Thing: ${t.id}\nType: ${t.type}\nVisibility: ${t.visibility}\nCreated: ${t.created_at}\n\nContent:\n${t.content}\n\nMetadata: ${JSON.stringify(t.metadata, null, 2)}`,
              },
            ],
          };
        }
        throw new Error(result.error || "Thing not found");
      }

      case "tenant_update_thing": {
        const data: UpdateThingRequest = {};
        if (args?.content) data.content = args.content as string;
        if (args?.visibility)
          data.visibility = args.visibility as "private" | "friends" | "public";
        if (args?.metadata)
          data.metadata = args.metadata as Record<string, unknown>;

        const result = await client.updateThing(args?.id as string, data);
        if (result.success) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Updated Thing ${args?.id}`,
              },
            ],
          };
        }
        throw new Error(result.error || "Failed to update Thing");
      }

      case "tenant_delete_thing": {
        const result = await client.deleteThing(args?.id as string);
        if (result.success) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Deleted Thing ${args?.id}`,
              },
            ],
          };
        }
        throw new Error(result.error || "Failed to delete Thing");
      }

      case "tenant_list_recent": {
        const result = await client.listThings({
          kind: args?.kind as string | undefined,
          limit: (args?.limit as number) || 10,
        });
        const things = result.items;
        if (things.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: "No recent Things found",
              },
            ],
          };
        }
        const formatted = things
          .map(
            (t) =>
              `- [${t.type}] ${t.id.slice(0, 8)}... (${new Date(t.created_at).toLocaleDateString()}): ${t.content.slice(0, 80)}${t.content.length > 80 ? "..." : ""}`
          )
          .join("\n");
        return {
          content: [
            {
              type: "text" as const,
              text: `Recent Things:\n\n${formatted}`,
            },
          ],
        };
      }

      case "tenant_add_tag": {
        await client.addTagToThing(args?.thing_id as string, args?.tag as string);
        return {
          content: [
            {
              type: "text" as const,
              text: `Added tag "${args?.tag}" to Thing ${args?.thing_id}`,
            },
          ],
        };
      }

      case "tenant_list_kinds": {
        const result = await client.listKinds();
        if (result.success && result.data) {
          const formatted = result.data
            .map((k) => `- ${k.icon} ${k.name} (${k.template})`)
            .join("\n");
          return {
            content: [
              {
                type: "text" as const,
                text: `Available Kinds:\n\n${formatted}`,
              },
            ],
          };
        }
        throw new Error(result.error || "Failed to list Kinds");
      }

      case "tenant_list_tags": {
        const result = await client.listTags();
        if (result.success && result.data) {
          const formatted = result.data.map((t) => `#${t.name}`).join(", ");
          return {
            content: [
              {
                type: "text" as const,
                text: `Tags: ${formatted || "(none)"}`,
              },
            ],
          };
        }
        throw new Error(result.error || "Failed to list tags");
      }

      case "tenant_create_link": {
        await client.createRelationship(
          args?.from_id as string,
          args?.to_id as string,
          (args?.type as string) || "links_to"
        );
        return {
          content: [
            {
              type: "text" as const,
              text: `Created ${args?.type || "links_to"} relationship from ${args?.from_id} to ${args?.to_id}`,
            },
          ],
        };
      }

      default:
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: "text" as const,
          text: `Error: ${message}`,
        },
      ],
      isError: true,
    };
  }
});

// ============================================================
// RESOURCES
// ============================================================

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    {
      uri: "tenant://things/recent",
      name: "Recent Things",
      description: "The 20 most recent Things for context",
      mimeType: "application/json",
    },
    {
      uri: "tenant://kinds",
      name: "Available Kinds",
      description: "All configured Kinds (types of Things)",
      mimeType: "application/json",
    },
    {
      uri: "tenant://tags",
      name: "All Tags",
      description: "All tags used in the system",
      mimeType: "application/json",
    },
  ],
}));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  try {
    if (uri === "tenant://things/recent") {
      const result = await client.listThings({ limit: 20 });
      return {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify(result.items, null, 2),
          },
        ],
      };
    }

    if (uri === "tenant://kinds") {
      const result = await client.listKinds();
      return {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify(result.data, null, 2),
          },
        ],
      };
    }

    if (uri === "tenant://tags") {
      const result = await client.listTags();
      return {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify(result.data, null, 2),
          },
        ],
      };
    }

    // Handle dynamic URIs like tenant://things/{id}
    const thingMatch = uri.match(/^tenant:\/\/things\/([a-f0-9-]+)$/);
    if (thingMatch) {
      const result = await client.getThing(thingMatch[1]);
      return {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify(result.data, null, 2),
          },
        ],
      };
    }

    throw new McpError(ErrorCode.InvalidRequest, `Unknown resource: ${uri}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new McpError(ErrorCode.InternalError, message);
  }
});

// ============================================================
// START SERVER
// ============================================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Tenant MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
