/**
 * Tenant API Client
 * Handles all communication with the Tenant backend
 */

export interface TenantConfig {
  baseUrl: string;
  apiKey: string;
}

export interface Thing {
  id: string;
  user_id: string;
  type: string;
  content: string;
  metadata: Record<string, unknown>;
  visibility: "private" | "friends" | "public";
  version: number;
  created_at: string;
  updated_at: string;
  edited_at?: string;
  deleted_at?: string;
  photos?: Photo[];
  comment_count?: number;
}

export interface Photo {
  id: string;
  thing_id: string;
  caption: string;
  order_index: number;
  content_type: string;
  filename: string;
  size: number;
  created_at: string;
}

export interface Kind {
  id: string;
  user_id: string;
  name: string;
  icon: string;
  template: string;
  attributes: Attribute[];
  commentable: boolean;
  reactable: boolean;
  created_at: string;
  updated_at: string;
}

export interface Attribute {
  name: string;
  type: string;
  required: boolean;
  options: string;
}

export interface Tag {
  id: string;
  user_id: string;
  name: string;
}

export interface CreateThingRequest {
  type: string;
  content: string;
  metadata?: Record<string, unknown>;
  visibility?: "private" | "friends" | "public";
}

export interface UpdateThingRequest {
  type?: string;
  content?: string;
  metadata?: Record<string, unknown>;
  visibility?: "private" | "friends" | "public";
}

export interface SearchParams {
  query?: string;
  kind?: string;
  tag?: string;
  visibility?: string;
  limit?: number;
  offset?: number;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export class TenantClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(config: TenantConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, ""); // Remove trailing slash
    this.apiKey = config.apiKey;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      "Content-Type": "application/json",
    };

    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Tenant API error: ${response.status} - ${error}`);
    }

    return response.json();
  }

  // ============================================================
  // THINGS
  // ============================================================

  async listThings(params: SearchParams = {}): Promise<PaginatedResponse<Thing>> {
    const searchParams = new URLSearchParams();
    if (params.query) searchParams.set("q", params.query);
    if (params.kind) searchParams.set("type", params.kind);
    if (params.tag) searchParams.set("tag", params.tag);
    if (params.visibility) searchParams.set("visibility", params.visibility);
    if (params.limit) searchParams.set("limit", params.limit.toString());
    if (params.offset) searchParams.set("offset", params.offset.toString());

    const query = searchParams.toString();
    const path = `/api/things${query ? `?${query}` : ""}`;
    return this.request<PaginatedResponse<Thing>>("GET", path);
  }

  async getThing(id: string): Promise<ApiResponse<Thing>> {
    return this.request<ApiResponse<Thing>>("GET", `/api/things/${id}`);
  }

  async createThing(data: CreateThingRequest): Promise<ApiResponse<Thing>> {
    return this.request<ApiResponse<Thing>>("POST", "/api/things", data);
  }

  async updateThing(
    id: string,
    data: UpdateThingRequest
  ): Promise<ApiResponse<Thing>> {
    return this.request<ApiResponse<Thing>>("PUT", `/api/things/${id}`, data);
  }

  async deleteThing(id: string): Promise<ApiResponse<void>> {
    return this.request<ApiResponse<void>>("DELETE", `/api/things/${id}`);
  }

  async searchThings(query: string, limit = 20): Promise<PaginatedResponse<Thing>> {
    return this.listThings({ query, limit });
  }

  // ============================================================
  // KINDS
  // ============================================================

  async listKinds(): Promise<ApiResponse<Kind[]>> {
    return this.request<ApiResponse<Kind[]>>("GET", "/api/kinds");
  }

  async getKind(id: string): Promise<ApiResponse<Kind>> {
    return this.request<ApiResponse<Kind>>("GET", `/api/kinds/${id}`);
  }

  // ============================================================
  // TAGS
  // ============================================================

  async listTags(): Promise<ApiResponse<Tag[]>> {
    return this.request<ApiResponse<Tag[]>>("GET", "/api/tags");
  }

  async addTagToThing(thingId: string, tagName: string): Promise<ApiResponse<void>> {
    return this.request<ApiResponse<void>>(
      "POST",
      `/api/things/${thingId}/tags`,
      { name: tagName }
    );
  }

  async removeTagFromThing(
    thingId: string,
    tagId: string
  ): Promise<ApiResponse<void>> {
    return this.request<ApiResponse<void>>(
      "DELETE",
      `/api/things/${thingId}/tags/${tagId}`
    );
  }

  // ============================================================
  // RELATIONSHIPS
  // ============================================================

  async getBacklinks(thingId: string): Promise<ApiResponse<Thing[]>> {
    return this.request<ApiResponse<Thing[]>>(
      "GET",
      `/api/things/${thingId}/backlinks`
    );
  }

  async createRelationship(
    fromId: string,
    toId: string,
    relType = "links_to"
  ): Promise<ApiResponse<void>> {
    return this.request<ApiResponse<void>>("POST", "/api/relationships", {
      from_id: fromId,
      to_id: toId,
      type: relType,
    });
  }

  // ============================================================
  // REACTIONS
  // ============================================================

  async addReaction(
    thingId: string,
    reactionType: "like" | "emoji",
    emoji?: string
  ): Promise<ApiResponse<void>> {
    return this.request<ApiResponse<void>>(
      "POST",
      `/api/things/${thingId}/reactions`,
      { reaction_type: reactionType, emoji }
    );
  }

  async removeReaction(thingId: string): Promise<ApiResponse<void>> {
    return this.request<ApiResponse<void>>(
      "DELETE",
      `/api/things/${thingId}/like`
    );
  }
}
