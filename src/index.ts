#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
    isInitializeRequest,
} from "@modelcontextprotocol/sdk/types.js";
import { google } from 'googleapis';
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { OAuth2Client, Credentials } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import open from 'open';
import os from 'os';
import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import {createEmailMessage, createEmailWithNodemailer} from "./utl.js";
import { createLabel, updateLabel, deleteLabel, listLabels, findLabelByName, getOrCreateLabel, GmailLabel } from "./label-manager.js";
import { createFilter, listFilters, getFilter, deleteFilter, filterTemplates, GmailFilterCriteria, GmailFilterAction } from "./filter-manager.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration paths
const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
const OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
const CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');
const TOKEN_PATH = process.env.GMAIL_MCP_TOKEN_PATH || CREDENTIALS_PATH;

// HTTP transport config
const HTTP_HOST = process.env.GMAIL_MCP_HOST || '127.0.0.1';
const HTTP_PORT = Number.parseInt(process.env.GMAIL_MCP_PORT || '3000', 10);
const HTTP_PATH = process.env.GMAIL_MCP_PATH || '/mcp';
const ENABLE_DNS_REBINDING_PROTECTION =
  (process.env.GMAIL_MCP_ENABLE_DNS_REBINDING_PROTECTION || '').toLowerCase() === 'true';
const ALLOWED_HOSTS = (process.env.GMAIL_MCP_ALLOWED_HOSTS || '')
  .split(',')
  .map((v) => v.trim())
  .filter(Boolean);
const ALLOWED_ORIGINS = (process.env.GMAIL_MCP_ALLOWED_ORIGINS || '')
  .split(',')
  .map((v) => v.trim())
  .filter(Boolean);

function escapeHtml(s: string): string {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

// Type definitions for Gmail API responses
interface GmailMessagePart {
    partId?: string;
    mimeType?: string;
    filename?: string;
    headers?: Array<{
        name: string;
        value: string;
    }>;
    body?: {
        attachmentId?: string;
        size?: number;
        data?: string;
    };
    parts?: GmailMessagePart[];
}

interface EmailAttachment {
    id: string;
    filename: string;
    mimeType: string;
    size: number;
}

interface EmailContent {
    text: string;
    html: string;
}

// OAuth2 configuration (shared single user across all sessions)
let oauth2Client: OAuth2Client;
let gmail: ReturnType<typeof google.gmail> | null = null;
let usingEnvTokens = false;
let authenticationPromise: Promise<void> | null = null;

/**
 * Recursively extract email body content from MIME message parts
 * Handles complex email structures with nested parts
 */
function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
    // Initialize containers for different content types
    let textContent = '';
    let htmlContent = '';

    // If the part has a body with data, process it based on MIME type
    if (messagePart.body && messagePart.body.data) {
        const content = Buffer.from(messagePart.body.data, 'base64').toString('utf8');

        // Store content based on its MIME type
        if (messagePart.mimeType === 'text/plain') {
            textContent = content;
        } else if (messagePart.mimeType === 'text/html') {
            htmlContent = content;
        }
    }

    // If the part has nested parts, recursively process them
    if (messagePart.parts && messagePart.parts.length > 0) {
        for (const part of messagePart.parts) {
            const { text, html } = extractEmailContent(part);
            if (text) textContent += text;
            if (html) htmlContent += html;
        }
    }

    // Return both plain text and HTML content
    return { text: textContent, html: htmlContent };
}

function parseKeys(keys: any): { client_id: string; client_secret?: string; redirect_uris?: string[] } {
    const k = keys.installed || keys.web;
    if (!k || !k.client_id) {
        throw new Error('Invalid OAuth keys format. Expected "installed" or "web" with client_id.');
    }
    return k;
}

function loadCredentialsFromEnv(): { client_id: string; client_secret?: string; redirect_uris?: string[] } | null {
    const jsonEnv = process.env.GMAIL_OAUTH_CREDENTIALS_JSON;
    if (jsonEnv) {
        try {
            return parseKeys(JSON.parse(jsonEnv));
        } catch (e) {
            throw new Error(`Invalid GMAIL_OAUTH_CREDENTIALS_JSON: ${e instanceof Error ? e.message : e}`);
        }
    }
    const b64 = process.env.GMAIL_OAUTH_CREDENTIALS_JSON_BASE64 || process.env.GMAIL_OAUTH_CREDENTIALS_BASE64;
    if (b64) {
        try {
            const decoded = Buffer.from(b64, 'base64').toString('utf-8');
            return parseKeys(JSON.parse(decoded));
        } catch (e) {
            throw new Error(`Invalid GMAIL_OAUTH_CREDENTIALS_JSON_BASE64: ${e instanceof Error ? e.message : e}`);
        }
    }
    return null;
}

function loadTokensFromEnv(): Credentials | null {
    const jsonEnv = process.env.GMAIL_MCP_TOKENS_JSON;
    if (jsonEnv) {
        try {
            const parsed = JSON.parse(jsonEnv);
            if (!parsed || typeof parsed !== 'object') throw new Error('Token payload must be a JSON object');
            return parsed;
        } catch (e) {
            throw new Error(`Invalid GMAIL_MCP_TOKENS_JSON: ${e instanceof Error ? e.message : e}`);
        }
    }
    const b64 = process.env.GMAIL_MCP_TOKENS_JSON_BASE64 || process.env.GMAIL_MCP_TOKENS_BASE64;
    if (b64) {
        try {
            const decoded = Buffer.from(b64, 'base64').toString('utf-8');
            const parsed = JSON.parse(decoded);
            if (!parsed || typeof parsed !== 'object') throw new Error('Token payload must be a JSON object');
            return parsed;
        } catch (e) {
            throw new Error(`Invalid GMAIL_MCP_TOKENS_JSON_BASE64: ${e instanceof Error ? e.message : e}`);
        }
    }
    return null;
}

function setupTokenRefreshPersistence() {
    if (!oauth2Client) return;
    oauth2Client.on('tokens', (newTokens) => {
        if (usingEnvTokens) {
            const current = oauth2Client.credentials || {};
            oauth2Client.setCredentials({
                ...current,
                ...newTokens,
                refresh_token: newTokens.refresh_token || (current as Credentials).refresh_token,
            });
            console.error('Tokens refreshed in memory (env token mode). Update GMAIL_MCP_TOKENS_JSON / GMAIL_MCP_TOKENS_JSON_BASE64 to persist.');
            return;
        }
        try {
            const current = JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8'));
            const updated = {
                ...current,
                ...newTokens,
                refresh_token: newTokens.refresh_token || current.refresh_token,
            };
            fs.writeFileSync(TOKEN_PATH, JSON.stringify(updated, null, 2), { mode: 0o600 });
            console.error('Tokens updated and saved to', TOKEN_PATH);
        } catch (err: any) {
            if (err?.code === 'ENOENT') {
                try {
                    fs.mkdirSync(path.dirname(TOKEN_PATH), { recursive: true });
                    fs.writeFileSync(TOKEN_PATH, JSON.stringify(newTokens, null, 2), { mode: 0o600 });
                } catch (e) {
                    console.error('Error saving initial tokens:', e);
                }
            } else {
                console.error('Error saving updated tokens:', err);
            }
        }
    });
}

async function loadCredentials() {
    try {
        if (!process.env.GMAIL_OAUTH_PATH && !fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true });
        }

        let keys: { client_id: string; client_secret?: string; redirect_uris?: string[] };
        const envKeys = loadCredentialsFromEnv();
        if (envKeys) {
            keys = envKeys;
        } else {
            const localOAuthPath = path.join(process.cwd(), 'gcp-oauth.keys.json');
            if (fs.existsSync(localOAuthPath)) {
                fs.copyFileSync(localOAuthPath, OAUTH_PATH);
                console.error('OAuth keys found in current directory, copied to global config.');
            }
            if (!fs.existsSync(OAUTH_PATH)) {
                console.error('Error: OAuth keys file not found. Use GMAIL_OAUTH_PATH or place gcp-oauth.keys.json in current directory or', CONFIG_DIR);
                process.exit(1);
            }
            const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
            keys = parseKeys(keysContent);
        }

        const callback =
            process.env.GMAIL_OAUTH_REDIRECT_URI
            || (process.argv[2] === 'auth' && process.argv[3]
                ? process.argv[3]
                : process.env.GMAIL_MCP_PORT
                    ? `http://127.0.0.1:${process.env.GMAIL_MCP_PORT}/oauth2callback`
                    : 'http://localhost:3000/oauth2callback');

        oauth2Client = new OAuth2Client(
            keys.client_id,
            keys.client_secret,
            callback
        );
        setupTokenRefreshPersistence();

        const envTokens = loadTokensFromEnv();
        if (envTokens) {
            usingEnvTokens = true;
            oauth2Client.setCredentials(envTokens);
            console.error('Tokens loaded from environment.');
        } else if (fs.existsSync(TOKEN_PATH)) {
            const credentials = JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8'));
            oauth2Client.setCredentials(credentials);
        }
    } catch (error) {
        console.error('Error loading credentials:', error);
        process.exit(1);
    }
}

async function authenticate() {
    const server = http.createServer();
    server.listen(3000);

    return new Promise<void>((resolve, reject) => {
        const authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: [
                'https://www.googleapis.com/auth/gmail.modify',
                'https://www.googleapis.com/auth/gmail.settings.basic'
            ],
        });

        console.log('Please visit this URL to authenticate:', authUrl);
        open(authUrl);

        server.on('request', async (req, res) => {
            if (!req.url?.startsWith('/oauth2callback')) return;

            const url = new URL(req.url, 'http://localhost:3000');
            const code = url.searchParams.get('code');

            if (!code) {
                res.writeHead(400);
                res.end('No code provided');
                reject(new Error('No code provided'));
                return;
            }

            try {
                const { tokens } = await oauth2Client.getToken(code);
                oauth2Client.setCredentials(tokens);
                if (!usingEnvTokens) {
                    fs.mkdirSync(path.dirname(TOKEN_PATH), { recursive: true });
                    fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2), { mode: 0o600 });
                }

                res.writeHead(200);
                res.end('Authentication successful! You can close this window.');
                server.close();
                resolve();
            } catch (error) {
                res.writeHead(500);
                res.end('Authentication failed');
                reject(error);
            }
        });
    });
}

async function ensureAuthenticated(): Promise<void> {
    if (authenticationPromise) await authenticationPromise;
    if (gmail) return;
    authenticationPromise = (async () => {
        if (oauth2Client.credentials?.refresh_token && !oauth2Client.credentials?.access_token) {
            await oauth2Client.getAccessToken();
        }
        if (!oauth2Client.credentials?.access_token) {
            throw new Error('Not authenticated. Run: npx gmail-mcp auth (or node dist/index.js auth)');
        }
        gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    })();
    await authenticationPromise;
    authenticationPromise = null;
}

async function runAuthCommand(): Promise<never> {
    await authenticate();
    console.log('Authentication completed successfully');
    process.exit(0);
}

// Schema definitions
const SendEmailSchema = z.object({
    to: z.array(z.string()).describe("List of recipient email addresses"),
    subject: z.string().describe("Email subject"),
    body: z.string().describe("Email body content (used for text/plain or when htmlBody not provided)"),
    htmlBody: z.string().optional().describe("HTML version of the email body"),
    mimeType: z.enum(['text/plain', 'text/html', 'multipart/alternative']).optional().default('text/plain').describe("Email content type"),
    cc: z.array(z.string()).optional().describe("List of CC recipients"),
    bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
    threadId: z.string().optional().describe("Thread ID to reply to"),
    inReplyTo: z.string().optional().describe("Message ID being replied to"),
    attachments: z.array(z.string()).optional().describe("List of file paths to attach to the email"),
});

const ReadEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to retrieve"),
});

const SearchEmailsSchema = z.object({
    query: z.string().describe("Gmail search query (e.g., 'from:example@gmail.com')"),
    maxResults: z.number().optional().describe("Maximum number of results to return"),
});

// Updated schema to include removeLabelIds
const ModifyEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to modify"),
    labelIds: z.array(z.string()).optional().describe("List of label IDs to apply"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to the message"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from the message"),
});

const DeleteEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to delete"),
});

// New schema for listing email labels
const ListEmailLabelsSchema = z.object({}).describe("Retrieves all available Gmail labels");

// Label management schemas
const CreateLabelSchema = z.object({
    name: z.string().describe("Name for the new label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Creates a new Gmail label");

const UpdateLabelSchema = z.object({
    id: z.string().describe("ID of the label to update"),
    name: z.string().optional().describe("New name for the label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Updates an existing Gmail label");

const DeleteLabelSchema = z.object({
    id: z.string().describe("ID of the label to delete"),
}).describe("Deletes a Gmail label");

const GetOrCreateLabelSchema = z.object({
    name: z.string().describe("Name of the label to get or create"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Gets an existing label by name or creates it if it doesn't exist");

// Schemas for batch operations
const BatchModifyEmailsSchema = z.object({
    messageIds: z.array(z.string()).describe("List of message IDs to modify"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to all messages"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from all messages"),
    batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});

const BatchDeleteEmailsSchema = z.object({
    messageIds: z.array(z.string()).describe("List of message IDs to delete"),
    batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});

// Filter management schemas
const CreateFilterSchema = z.object({
    criteria: z.object({
        from: z.string().optional().describe("Sender email address to match"),
        to: z.string().optional().describe("Recipient email address to match"),
        subject: z.string().optional().describe("Subject text to match"),
        query: z.string().optional().describe("Gmail search query (e.g., 'has:attachment')"),
        negatedQuery: z.string().optional().describe("Text that must NOT be present"),
        hasAttachment: z.boolean().optional().describe("Whether to match emails with attachments"),
        excludeChats: z.boolean().optional().describe("Whether to exclude chat messages"),
        size: z.number().optional().describe("Email size in bytes"),
        sizeComparison: z.enum(['unspecified', 'smaller', 'larger']).optional().describe("Size comparison operator")
    }).describe("Criteria for matching emails"),
    action: z.object({
        addLabelIds: z.array(z.string()).optional().describe("Label IDs to add to matching emails"),
        removeLabelIds: z.array(z.string()).optional().describe("Label IDs to remove from matching emails"),
        forward: z.string().optional().describe("Email address to forward matching emails to")
    }).describe("Actions to perform on matching emails")
}).describe("Creates a new Gmail filter");

const ListFiltersSchema = z.object({}).describe("Retrieves all Gmail filters");

const GetFilterSchema = z.object({
    filterId: z.string().describe("ID of the filter to retrieve")
}).describe("Gets details of a specific Gmail filter");

const DeleteFilterSchema = z.object({
    filterId: z.string().describe("ID of the filter to delete")
}).describe("Deletes a Gmail filter");

const CreateFilterFromTemplateSchema = z.object({
    template: z.enum(['fromSender', 'withSubject', 'withAttachments', 'largeEmails', 'containingText', 'mailingList']).describe("Pre-defined filter template to use"),
    parameters: z.object({
        senderEmail: z.string().optional().describe("Sender email (for fromSender template)"),
        subjectText: z.string().optional().describe("Subject text (for withSubject template)"),
        searchText: z.string().optional().describe("Text to search for (for containingText template)"),
        listIdentifier: z.string().optional().describe("Mailing list identifier (for mailingList template)"),
        sizeInBytes: z.number().optional().describe("Size threshold in bytes (for largeEmails template)"),
        labelIds: z.array(z.string()).optional().describe("Label IDs to apply"),
        archive: z.boolean().optional().describe("Whether to archive (skip inbox)"),
        markAsRead: z.boolean().optional().describe("Whether to mark as read"),
        markImportant: z.boolean().optional().describe("Whether to mark as important")
    }).describe("Template-specific parameters")
}).describe("Creates a filter using a pre-defined template");

const DownloadAttachmentSchema = z.object({
    messageId: z.string().describe("ID of the email message containing the attachment"),
    attachmentId: z.string().describe("ID of the attachment to download"),
    filename: z.string().optional().describe("Filename to save the attachment as (if not provided, uses original filename)"),
    savePath: z.string().optional().describe("Directory path to save the attachment (defaults to current directory)"),
});


// Main function
async function main() {
    await loadCredentials();

    if (process.argv[2] === 'auth') {
        try {
            await runAuthCommand();
        } catch (err) {
            console.error('Authentication failed:', err);
            process.exit(1);
        }
        return;
    }

    // MCP server and handlers (shared by all sessions; gmail is set in ensureAuthenticated)
    const server = new Server(
        { name: "gmail", version: "1.0.0" },
        { capabilities: { tools: {} } }
    );

    function registerMcpHandlers(s: Server) {
    s.setRequestHandler(ListToolsRequestSchema, async () => {
        await ensureAuthenticated();
        return {
        tools: [
            {
                name: "send_email",
                description: "Sends a new email",
                inputSchema: zodToJsonSchema(SendEmailSchema),
            },
            {
                name: "draft_email",
                description: "Draft a new email",
                inputSchema: zodToJsonSchema(SendEmailSchema),
            },
            {
                name: "read_email",
                description: "Retrieves the content of a specific email",
                inputSchema: zodToJsonSchema(ReadEmailSchema),
            },
            {
                name: "search_emails",
                description: "Searches for emails using Gmail search syntax",
                inputSchema: zodToJsonSchema(SearchEmailsSchema),
            },
            {
                name: "modify_email",
                description: "Modifies email labels (move to different folders)",
                inputSchema: zodToJsonSchema(ModifyEmailSchema),
            },
            {
                name: "delete_email",
                description: "Permanently deletes an email",
                inputSchema: zodToJsonSchema(DeleteEmailSchema),
            },
            {
                name: "list_email_labels",
                description: "Retrieves all available Gmail labels",
                inputSchema: zodToJsonSchema(ListEmailLabelsSchema),
            },
            {
                name: "batch_modify_emails",
                description: "Modifies labels for multiple emails in batches",
                inputSchema: zodToJsonSchema(BatchModifyEmailsSchema),
            },
            {
                name: "batch_delete_emails",
                description: "Permanently deletes multiple emails in batches",
                inputSchema: zodToJsonSchema(BatchDeleteEmailsSchema),
            },
            {
                name: "create_label",
                description: "Creates a new Gmail label",
                inputSchema: zodToJsonSchema(CreateLabelSchema),
            },
            {
                name: "update_label",
                description: "Updates an existing Gmail label",
                inputSchema: zodToJsonSchema(UpdateLabelSchema),
            },
            {
                name: "delete_label",
                description: "Deletes a Gmail label",
                inputSchema: zodToJsonSchema(DeleteLabelSchema),
            },
            {
                name: "get_or_create_label",
                description: "Gets an existing label by name or creates it if it doesn't exist",
                inputSchema: zodToJsonSchema(GetOrCreateLabelSchema),
            },
            {
                name: "create_filter",
                description: "Creates a new Gmail filter with custom criteria and actions",
                inputSchema: zodToJsonSchema(CreateFilterSchema),
            },
            {
                name: "list_filters",
                description: "Retrieves all Gmail filters",
                inputSchema: zodToJsonSchema(ListFiltersSchema),
            },
            {
                name: "get_filter",
                description: "Gets details of a specific Gmail filter",
                inputSchema: zodToJsonSchema(GetFilterSchema),
            },
            {
                name: "delete_filter",
                description: "Deletes a Gmail filter",
                inputSchema: zodToJsonSchema(DeleteFilterSchema),
            },
            {
                name: "create_filter_from_template",
                description: "Creates a filter using a pre-defined template for common scenarios",
                inputSchema: zodToJsonSchema(CreateFilterFromTemplateSchema),
            },
            {
                name: "download_attachment",
                description: "Downloads an email attachment to a specified location",
                inputSchema: zodToJsonSchema(DownloadAttachmentSchema),
            },
        ],
    };
    });

    s.setRequestHandler(CallToolRequestSchema, async (request) => {
        await ensureAuthenticated();
        const g = gmail!;
        const { name, arguments: args } = request.params;

        async function handleEmailAction(action: "send" | "draft", validatedArgs: any) {
            let message: string;
            
            try {
                // Check if we have attachments
                if (validatedArgs.attachments && validatedArgs.attachments.length > 0) {
                    // Use Nodemailer to create properly formatted RFC822 message
                    message = await createEmailWithNodemailer(validatedArgs);
                    
                    if (action === "send") {
                        const encodedMessage = Buffer.from(message).toString('base64')
                            .replace(/\+/g, '-')
                            .replace(/\//g, '_')
                            .replace(/=+$/, '');

                        const result = await g.users.messages.send({
                            userId: 'me',
                            requestBody: {
                                raw: encodedMessage,
                                ...(validatedArgs.threadId && { threadId: validatedArgs.threadId })
                            }
                        });
                        
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email sent successfully with ID: ${result.data.id}`,
                                },
                            ],
                        };
                    } else {
                        // For drafts with attachments, use the raw message
                        const encodedMessage = Buffer.from(message).toString('base64')
                            .replace(/\+/g, '-')
                            .replace(/\//g, '_')
                            .replace(/=+$/, '');
                        
                        const messageRequest = {
                            raw: encodedMessage,
                            ...(validatedArgs.threadId && { threadId: validatedArgs.threadId })
                        };
                        
                        const response = await g.users.drafts.create({
                            userId: 'me',
                            requestBody: {
                                message: messageRequest,
                            },
                        });
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email draft created successfully with ID: ${response.data.id}`,
                                },
                            ],
                        };
                    }
                } else {
                    // For emails without attachments, use the existing simple method
                    message = createEmailMessage(validatedArgs);
                    
                    const encodedMessage = Buffer.from(message).toString('base64')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=+$/, '');

                    // Define the type for messageRequest
                    interface GmailMessageRequest {
                        raw: string;
                        threadId?: string;
                    }

                    const messageRequest: GmailMessageRequest = {
                        raw: encodedMessage,
                    };

                    // Add threadId if specified
                    if (validatedArgs.threadId) {
                        messageRequest.threadId = validatedArgs.threadId;
                    }

                    if (action === "send") {
                        const response = await g.users.messages.send({
                            userId: 'me',
                            requestBody: messageRequest,
                        });
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email sent successfully with ID: ${response.data.id}`,
                                },
                            ],
                        };
                    } else {
                        const response = await g.users.drafts.create({
                            userId: 'me',
                            requestBody: {
                                message: messageRequest,
                        },
                        });
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email draft created successfully with ID: ${response.data.id}`,
                                },
                            ],
                        };
                    }
                }
            } catch (error: any) {
                // Log attachment-related errors for debugging
                if (validatedArgs.attachments && validatedArgs.attachments.length > 0) {
                    console.error(`Failed to send email with ${validatedArgs.attachments.length} attachments:`, error.message);
                }
                throw error;
            }
        }

        // Helper function to process operations in batches
        async function processBatches<T, U>(
            items: T[],
            batchSize: number,
            processFn: (batch: T[]) => Promise<U[]>
        ): Promise<{ successes: U[], failures: { item: T, error: Error }[] }> {
            const successes: U[] = [];
            const failures: { item: T, error: Error }[] = [];
            
            // Process in batches
            for (let i = 0; i < items.length; i += batchSize) {
                const batch = items.slice(i, i + batchSize);
                try {
                    const results = await processFn(batch);
                    successes.push(...results);
                } catch (error) {
                    // If batch fails, try individual items
                    for (const item of batch) {
                        try {
                            const result = await processFn([item]);
                            successes.push(...result);
                        } catch (itemError) {
                            failures.push({ item, error: itemError as Error });
                        }
                    }
                }
            }
            
            return { successes, failures };
        }

        try {
            switch (name) {
                case "send_email":
                case "draft_email": {
                    const validatedArgs = SendEmailSchema.parse(args);
                    const action = name === "send_email" ? "send" : "draft";
                    return await handleEmailAction(action, validatedArgs);
                }

                case "read_email": {
                    const validatedArgs = ReadEmailSchema.parse(args);
                    const response = await g.users.messages.get({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        format: 'full',
                    });

                    const headers = response.data.payload?.headers || [];
                    const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                    const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                    const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                    const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';
                    const threadId = response.data.threadId || '';

                    // Extract email content using the recursive function
                    const { text, html } = extractEmailContent(response.data.payload as GmailMessagePart || {});

                    // Use plain text content if available, otherwise use HTML content
                    // (optionally, you could implement HTML-to-text conversion here)
                    let body = text || html || '';

                    // If we only have HTML content, add a note for the user
                    const contentTypeNote = !text && html ?
                        '[Note: This email is HTML-formatted. Plain text version not available.]\n\n' : '';

                    // Get attachment information
                    const attachments: EmailAttachment[] = [];
                    const processAttachmentParts = (part: GmailMessagePart, path: string = '') => {
                        if (part.body && part.body.attachmentId) {
                            const filename = part.filename || `attachment-${part.body.attachmentId}`;
                            attachments.push({
                                id: part.body.attachmentId,
                                filename: filename,
                                mimeType: part.mimeType || 'application/octet-stream',
                                size: part.body.size || 0
                            });
                        }

                        if (part.parts) {
                            part.parts.forEach((subpart: GmailMessagePart) =>
                                processAttachmentParts(subpart, `${path}/parts`)
                            );
                        }
                    };

                    if (response.data.payload) {
                        processAttachmentParts(response.data.payload as GmailMessagePart);
                    }

                    // Add attachment info to output if any are present
                    const attachmentInfo = attachments.length > 0 ?
                        `\n\nAttachments (${attachments.length}):\n` +
                        attachments.map(a => `- ${a.filename} (${a.mimeType}, ${Math.round(a.size/1024)} KB, ID: ${a.id})`).join('\n') : '';

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Thread ID: ${threadId}\nSubject: ${subject}\nFrom: ${from}\nTo: ${to}\nDate: ${date}\n\n${contentTypeNote}${body}${attachmentInfo}`,
                            },
                        ],
                    };
                }

                case "search_emails": {
                    const validatedArgs = SearchEmailsSchema.parse(args);
                    const response = await g.users.messages.list({
                        userId: 'me',
                        q: validatedArgs.query,
                        maxResults: validatedArgs.maxResults || 10,
                    });

                    const messages = response.data.messages || [];
                    const results = await Promise.all(
                        messages.map(async (msg) => {
                            const detail = await g.users.messages.get({
                                userId: 'me',
                                id: msg.id!,
                                format: 'metadata',
                                metadataHeaders: ['Subject', 'From', 'Date'],
                            });
                            const headers = detail.data.payload?.headers || [];
                            return {
                                id: msg.id,
                                subject: headers.find(h => h.name === 'Subject')?.value || '',
                                from: headers.find(h => h.name === 'From')?.value || '',
                                date: headers.find(h => h.name === 'Date')?.value || '',
                            };
                        })
                    );

                    return {
                        content: [
                            {
                                type: "text",
                                text: results.map(r =>
                                    `ID: ${r.id}\nSubject: ${r.subject}\nFrom: ${r.from}\nDate: ${r.date}\n`
                                ).join('\n'),
                            },
                        ],
                    };
                }

                // Updated implementation for the modify_email handler
                case "modify_email": {
                    const validatedArgs = ModifyEmailSchema.parse(args);
                    
                    // Prepare request body
                    const requestBody: any = {};
                    
                    if (validatedArgs.labelIds) {
                        requestBody.addLabelIds = validatedArgs.labelIds;
                    }
                    
                    if (validatedArgs.addLabelIds) {
                        requestBody.addLabelIds = validatedArgs.addLabelIds;
                    }
                    
                    if (validatedArgs.removeLabelIds) {
                        requestBody.removeLabelIds = validatedArgs.removeLabelIds;
                    }
                    
                    await g.users.messages.modify({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        requestBody: requestBody,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} labels updated successfully`,
                            },
                        ],
                    };
                }

                case "delete_email": {
                    const validatedArgs = DeleteEmailSchema.parse(args);
                    await g.users.messages.delete({
                        userId: 'me',
                        id: validatedArgs.messageId,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} deleted successfully`,
                            },
                        ],
                    };
                }

                case "list_email_labels": {
                    const labelResults = await listLabels(gmail);
                    const systemLabels = labelResults.system;
                    const userLabels = labelResults.user;

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Found ${labelResults.count.total} labels (${labelResults.count.system} system, ${labelResults.count.user} user):\n\n` +
                                    "System Labels:\n" +
                                    systemLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n') +
                                    "\nUser Labels:\n" +
                                    userLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n')
                            },
                        ],
                    };
                }

                case "batch_modify_emails": {
                    const validatedArgs = BatchModifyEmailsSchema.parse(args);
                    const messageIds = validatedArgs.messageIds;
                    const batchSize = validatedArgs.batchSize || 50;
                    
                    // Prepare request body
                    const requestBody: any = {};
                    
                    if (validatedArgs.addLabelIds) {
                        requestBody.addLabelIds = validatedArgs.addLabelIds;
                    }
                    
                    if (validatedArgs.removeLabelIds) {
                        requestBody.removeLabelIds = validatedArgs.removeLabelIds;
                    }

                    // Process messages in batches
                    const { successes, failures } = await processBatches(
                        messageIds,
                        batchSize,
                        async (batch) => {
                            const results = await Promise.all(
                                batch.map(async (messageId) => {
                                    const result = await g.users.messages.modify({
                                        userId: 'me',
                                        id: messageId,
                                        requestBody: requestBody,
                                    });
                                    return { messageId, success: true };
                                })
                            );
                            return results;
                        }
                    );

                    // Generate summary of the operation
                    const successCount = successes.length;
                    const failureCount = failures.length;
                    
                    let resultText = `Batch label modification complete.\n`;
                    resultText += `Successfully processed: ${successCount} messages\n`;
                    
                    if (failureCount > 0) {
                        resultText += `Failed to process: ${failureCount} messages\n\n`;
                        resultText += `Failed message IDs:\n`;
                        resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: resultText,
                            },
                        ],
                    };
                }

                case "batch_delete_emails": {
                    const validatedArgs = BatchDeleteEmailsSchema.parse(args);
                    const messageIds = validatedArgs.messageIds;
                    const batchSize = validatedArgs.batchSize || 50;

                    // Process messages in batches
                    const { successes, failures } = await processBatches(
                        messageIds,
                        batchSize,
                        async (batch) => {
                            const results = await Promise.all(
                                batch.map(async (messageId) => {
                                    await g.users.messages.delete({
                                        userId: 'me',
                                        id: messageId,
                                    });
                                    return { messageId, success: true };
                                })
                            );
                            return results;
                        }
                    );

                    // Generate summary of the operation
                    const successCount = successes.length;
                    const failureCount = failures.length;
                    
                    let resultText = `Batch delete operation complete.\n`;
                    resultText += `Successfully deleted: ${successCount} messages\n`;
                    
                    if (failureCount > 0) {
                        resultText += `Failed to delete: ${failureCount} messages\n\n`;
                        resultText += `Failed message IDs:\n`;
                        resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: resultText,
                            },
                        ],
                    };
                }

                // New label management handlers
                case "create_label": {
                    const validatedArgs = CreateLabelSchema.parse(args);
                    const result = await createLabel(gmail, validatedArgs.name, {
                        messageListVisibility: validatedArgs.messageListVisibility,
                        labelListVisibility: validatedArgs.labelListVisibility,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Label created successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }

                case "update_label": {
                    const validatedArgs = UpdateLabelSchema.parse(args);
                    
                    // Prepare request body with only the fields that were provided
                    const updates: any = {};
                    if (validatedArgs.name) updates.name = validatedArgs.name;
                    if (validatedArgs.messageListVisibility) updates.messageListVisibility = validatedArgs.messageListVisibility;
                    if (validatedArgs.labelListVisibility) updates.labelListVisibility = validatedArgs.labelListVisibility;
                    
                    const result = await updateLabel(gmail, validatedArgs.id, updates);

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Label updated successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }

                case "delete_label": {
                    const validatedArgs = DeleteLabelSchema.parse(args);
                    const result = await deleteLabel(gmail, validatedArgs.id);

                    return {
                        content: [
                            {
                                type: "text",
                                text: result.message,
                            },
                        ],
                    };
                }

                case "get_or_create_label": {
                    const validatedArgs = GetOrCreateLabelSchema.parse(args);
                    const result = await getOrCreateLabel(gmail, validatedArgs.name, {
                        messageListVisibility: validatedArgs.messageListVisibility,
                        labelListVisibility: validatedArgs.labelListVisibility,
                    });

                    const action = result.type === 'user' && result.name === validatedArgs.name ? 'found existing' : 'created new';
                    
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Successfully ${action} label:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }


                // Filter management handlers
                case "create_filter": {
                    const validatedArgs = CreateFilterSchema.parse(args);
                    const result = await createFilter(g, validatedArgs.criteria, validatedArgs.action);

                    // Format criteria for display
                    const criteriaText = Object.entries(validatedArgs.criteria)
                        .filter(([_, value]) => value !== undefined)
                        .map(([key, value]) => `${key}: ${value}`)
                        .join(', ');

                    // Format actions for display
                    const actionText = Object.entries(validatedArgs.action)
                        .filter(([_, value]) => value !== undefined && (Array.isArray(value) ? value.length > 0 : true))
                        .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
                        .join(', ');

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Filter created successfully:\nID: ${result.id}\nCriteria: ${criteriaText}\nActions: ${actionText}`,
                            },
                        ],
                    };
                }

                case "list_filters": {
                    const result = await listFilters(gmail);
                    const filters = result.filters;

                    if (filters.length === 0) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: "No filters found.",
                                },
                            ],
                        };
                    }

                    const filtersText = filters.map((filter: any) => {
                        const criteriaEntries = Object.entries(filter.criteria || {})
                            .filter(([_, value]) => value !== undefined)
                            .map(([key, value]) => `${key}: ${value}`)
                            .join(', ');
                        
                        const actionEntries = Object.entries(filter.action || {})
                            .filter(([_, value]) => value !== undefined && (Array.isArray(value) ? value.length > 0 : true))
                            .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
                            .join(', ');

                        return `ID: ${filter.id}\nCriteria: ${criteriaEntries}\nActions: ${actionEntries}\n`;
                    }).join('\n');

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Found ${result.count} filters:\n\n${filtersText}`,
                            },
                        ],
                    };
                }

                case "get_filter": {
                    const validatedArgs = GetFilterSchema.parse(args);
                    const result = await getFilter(gmail, validatedArgs.filterId);

                    const criteriaText = Object.entries(result.criteria || {})
                        .filter(([_, value]) => value !== undefined)
                        .map(([key, value]) => `${key}: ${value}`)
                        .join(', ');
                    
                    const actionText = Object.entries(result.action || {})
                        .filter(([_, value]) => value !== undefined && (Array.isArray(value) ? value.length > 0 : true))
                        .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
                        .join(', ');

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Filter details:\nID: ${result.id}\nCriteria: ${criteriaText}\nActions: ${actionText}`,
                            },
                        ],
                    };
                }

                case "delete_filter": {
                    const validatedArgs = DeleteFilterSchema.parse(args);
                    const result = await deleteFilter(gmail, validatedArgs.filterId);

                    return {
                        content: [
                            {
                                type: "text",
                                text: result.message,
                            },
                        ],
                    };
                }

                case "create_filter_from_template": {
                    const validatedArgs = CreateFilterFromTemplateSchema.parse(args);
                    const template = validatedArgs.template;
                    const params = validatedArgs.parameters;

                    let filterConfig;
                    
                    switch (template) {
                        case 'fromSender':
                            if (!params.senderEmail) throw new Error("senderEmail is required for fromSender template");
                            filterConfig = filterTemplates.fromSender(params.senderEmail, params.labelIds, params.archive);
                            break;
                        case 'withSubject':
                            if (!params.subjectText) throw new Error("subjectText is required for withSubject template");
                            filterConfig = filterTemplates.withSubject(params.subjectText, params.labelIds, params.markAsRead);
                            break;
                        case 'withAttachments':
                            filterConfig = filterTemplates.withAttachments(params.labelIds);
                            break;
                        case 'largeEmails':
                            if (!params.sizeInBytes) throw new Error("sizeInBytes is required for largeEmails template");
                            filterConfig = filterTemplates.largeEmails(params.sizeInBytes, params.labelIds);
                            break;
                        case 'containingText':
                            if (!params.searchText) throw new Error("searchText is required for containingText template");
                            filterConfig = filterTemplates.containingText(params.searchText, params.labelIds, params.markImportant);
                            break;
                        case 'mailingList':
                            if (!params.listIdentifier) throw new Error("listIdentifier is required for mailingList template");
                            filterConfig = filterTemplates.mailingList(params.listIdentifier, params.labelIds, params.archive);
                            break;
                        default:
                            throw new Error(`Unknown template: ${template}`);
                    }

                    const result = await createFilter(g, filterConfig.criteria, filterConfig.action);

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Filter created from template '${template}':\nID: ${result.id}\nTemplate used: ${template}`,
                            },
                        ],
                    };
                }
                case "download_attachment": {
                    const validatedArgs = DownloadAttachmentSchema.parse(args);
                    
                    try {
                        // Get the attachment data from Gmail API
                        const attachmentResponse = await g.users.messages.attachments.get({
                            userId: 'me',
                            messageId: validatedArgs.messageId,
                            id: validatedArgs.attachmentId,
                        });

                        if (!attachmentResponse.data.data) {
                            throw new Error('No attachment data received');
                        }

                        // Decode the base64 data
                        const data = attachmentResponse.data.data;
                        const buffer = Buffer.from(data, 'base64url');

                        // Determine save path and filename
                        const savePath = validatedArgs.savePath || process.cwd();
                        let filename = validatedArgs.filename;
                        
                        if (!filename) {
                            // Get original filename from message if not provided
                            const messageResponse = await g.users.messages.get({
                                userId: 'me',
                                id: validatedArgs.messageId,
                                format: 'full',
                            });
                            
                            // Find the attachment part to get original filename
                            const findAttachment = (part: any): string | null => {
                                if (part.body && part.body.attachmentId === validatedArgs.attachmentId) {
                                    return part.filename || `attachment-${validatedArgs.attachmentId}`;
                                }
                                if (part.parts) {
                                    for (const subpart of part.parts) {
                                        const found = findAttachment(subpart);
                                        if (found) return found;
                                    }
                                }
                                return null;
                            };
                            
                            filename = findAttachment(messageResponse.data.payload) || `attachment-${validatedArgs.attachmentId}`;
                        }

                        // Ensure save directory exists
                        if (!fs.existsSync(savePath)) {
                            fs.mkdirSync(savePath, { recursive: true });
                        }

                        // Write file
                        const fullPath = path.join(savePath, filename);
                        fs.writeFileSync(fullPath, buffer);

                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Attachment downloaded successfully:\nFile: ${filename}\nSize: ${buffer.length} bytes\nSaved to: ${fullPath}`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Failed to download attachment: ${error.message}`,
                                },
                            ],
                        };
                    }
                }

                default:
                    throw new Error(`Unknown tool: ${name}`);
            }
        } catch (error: any) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Error: ${error.message}`,
                    },
                ],
            };
        }
    });
    }

    registerMcpHandlers(server);

    function createMcpServer(): Server {
        const s = new Server(
            { name: "gmail", version: "1.0.0" },
            { capabilities: { tools: {} } }
        );
        registerMcpHandlers(s);
        return s;
    }

    interface SessionState {
        server: Server;
        transport: StreamableHTTPServerTransport;
    }
    const sessions = new Map<string, SessionState>();

    function isInitializePayload(payload: unknown): boolean {
        if (Array.isArray(payload)) {
            return payload.some((m) => isInitializeRequest(m));
        }
        return isInitializeRequest(payload);
    }

    function createBadRequestResponse(message: string): object {
        return {
            jsonrpc: "2.0",
            error: { code: -32000, message },
            id: null,
        };
    }

    async function getTransportForRequest(
        req: express.Request,
        requestBody: unknown
    ): Promise<StreamableHTTPServerTransport | null> {
        const sessionIdHeader = req.headers["mcp-session-id"];
        const sessionId = typeof sessionIdHeader === "string" ? sessionIdHeader.trim() : null;

        if (sessionId) {
            const state = sessions.get(sessionId);
            if (state) return state.transport;
            return null;
        }
        if (req.method !== "POST" || !isInitializePayload(requestBody)) {
            return null;
        }
        const newSessionId = uuidv4();
        const sessionServer = createMcpServer();
        const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => newSessionId,
            enableDnsRebindingProtection: ENABLE_DNS_REBINDING_PROTECTION,
            allowedHosts: ALLOWED_HOSTS.length ? ALLOWED_HOSTS : undefined,
            allowedOrigins: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : undefined,
        });
        transport.onclose = () => sessions.delete(newSessionId);
        transport.onerror = (err: Error) => console.error("Streamable HTTP transport error", err.message);
        await sessionServer.connect(transport);
        sessions.set(newSessionId, { server: sessionServer, transport });
        return transport;
    }

    function installGracefulShutdown(httpServer: import("http").Server): void {
        let shutdownStarted = false;
        const shutdown = async (signal: string) => {
            if (shutdownStarted) return;
            shutdownStarted = true;
            for (const [, state] of sessions.entries()) {
                try {
                    await state.transport.close();
                } catch (_) {}
            }
            sessions.clear();
            await server.close();
            await new Promise<void>((resolve, reject) => {
                httpServer.close((err) => (err ? reject(err) : resolve()));
            });
            process.exit(0);
        };
        process.on("SIGINT", () => void shutdown("SIGINT"));
        process.on("SIGTERM", () => void shutdown("SIGTERM"));
    }

    async function startHttpServer(): Promise<void> {
        if (!Number.isInteger(HTTP_PORT) || HTTP_PORT < 1 || HTTP_PORT > 65535) {
            throw new Error(`Invalid GMAIL_MCP_PORT: ${process.env.GMAIL_MCP_PORT}`);
        }
        const app = express();
        app.use(express.json({ limit: "4mb" }));

        app.get("/healthz", (_req, res) => {
            res.status(200).json({ status: "ok", sessions: sessions.size });
        });

        // In-app OAuth: serve consent entrypoint and callback, write tokens to GMAIL_MCP_TOKEN_PATH
        const GMAIL_SCOPES = [
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.settings.basic",
        ];

        app.get("/auth", (_req, res) => {
            const authUrl = oauth2Client.generateAuthUrl({
                access_type: "offline",
                scope: GMAIL_SCOPES,
                prompt: "consent",
            });
            res.redirect(302, authUrl);
        });

        app.get("/oauth2callback", async (req, res) => {
            const code = req.query.code as string | undefined;
            const errorQuery = req.query.error as string | undefined;
            if (errorQuery) {
                res.status(400).send(
                    `<!DOCTYPE html><html><body><h1>Authentication failed</h1><p>Error: ${escapeHtml(String(errorQuery))}</p></body></html>`
                );
                return;
            }
            if (!code) {
                res.status(400).send(
                    "<!DOCTYPE html><html><body><h1>Missing code</h1><p>No authorization code received.</p></body></html>"
                );
                return;
            }
            try {
                const { tokens } = await oauth2Client.getToken(code);
                oauth2Client.setCredentials(tokens);
                if (!usingEnvTokens) {
                    fs.mkdirSync(path.dirname(TOKEN_PATH), { recursive: true });
                    fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2), { mode: 0o600 });
                }
                res.status(200).send(
                    "<!DOCTYPE html><html><body><h1>Authentication successful</h1><p>Tokens saved. You can close this window.</p></body></html>"
                );
            } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                res.status(500).send(
                    `<!DOCTYPE html><html><body><h1>Authentication failed</h1><p>${escapeHtml(msg)}</p></body></html>`
                );
            }
        });

        const handleMcpRequest = async (req: express.Request, res: express.Response): Promise<void> => {
            try {
                const transport = await getTransportForRequest(req, req.body);
                if (!transport) {
                    const sessionId = req.headers["mcp-session-id"];
                    const message = sessionId
                        ? "Bad Request: Unknown or expired session. Send an initialize request to start a new session."
                        : "Bad Request: Server not initialized. Send an initialize request first.";
                    res.status(400).json(createBadRequestResponse(message));
                    return;
                }
                await transport.handleRequest(req, res, req.body);
            } catch (error) {
                if (!res.headersSent) {
                    res.status(500).json({
                        jsonrpc: "2.0",
                        error: { code: -32603, message: "Internal server error" },
                        id: null,
                    });
                }
            }
        };

        app.post(HTTP_PATH, handleMcpRequest);
        app.get(HTTP_PATH, handleMcpRequest);
        app.delete(HTTP_PATH, handleMcpRequest);

        await new Promise<void>((resolve, reject) => {
            const httpServer = app.listen(HTTP_PORT, HTTP_HOST, () => {
                installGracefulShutdown(httpServer);
                console.error("Gmail MCP Streamable HTTP server listening", { host: HTTP_HOST, port: HTTP_PORT, path: HTTP_PATH });
                resolve();
            });
            httpServer.on("error", reject);
        });
    }

    await startHttpServer();
}

main().catch((error) => {
    console.error('Server error:', error);
    process.exit(1);
});
