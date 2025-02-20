import { z } from 'zod';

// Individual query schemas
const clientIDQuerySchema = z.object({
  clientID: z.string(),
});

const tenantQuerySchema = z.object({
  tenant: z.string(),
  product: z.string(),
  strategy: z.enum(['saml', 'oidc']).optional(),
});

const entityIdQuerySchema = z.object({
  entityId: z.string(),
});

const tenantArrayQuerySchema = z.object({
  tenant: z.array(z.string()),
  product: z.string(),
  sort: z.boolean().optional(),
});

// Combined schema for GetConnectionsQuery
export const getConnectionsQuerySchema = z.union([
  clientIDQuerySchema,
  tenantQuerySchema,
  entityIdQuerySchema,
  tenantArrayQuerySchema,
]);
