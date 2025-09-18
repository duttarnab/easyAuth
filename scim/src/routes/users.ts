import { Router, Request, Response } from 'express';
import { ScimUser } from '../models/User';

export const usersRouter = Router();

function requireBearer(req: Request, res: Response): boolean {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    res.status(401).setHeader('WWW-Authenticate', 'Bearer realm="scim"').json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '401',
      detail: 'Unauthorized'
    });
    return false;
  }
  // In real scenarios, validate the token or API key here
  return true;
}

function toScimUser(u: any) {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: u._id.toString(),
    userName: u.email,
    name: { formatted: u.name },
    active: u.isVerified,
    emails: [{ value: u.email, primary: true }],
    meta: {
      resourceType: 'User',
      created: u.createdAt,
      lastModified: u.updatedAt
    }
  };
}

usersRouter.get('/', async (req, res) => {
  if (!requireBearer(req, res)) return;
  const filter = (req.query.filter as string) || '';
  const startIndex = Number(req.query.startIndex || 1);
  const count = Number(req.query.count || 50);

  let query: any = {};
  if (filter) {
    // Basic filter support: userName eq "value"
    const match = filter.match(/userName\s+eq\s+\"(.+?)\"/i);
    if (match) {
      query.email = match[1].toLowerCase();
    }
  }

  const totalResults = await ScimUser.countDocuments(query);
  const items = await ScimUser.find(query)
    .skip(Math.max(0, startIndex - 1))
    .limit(Math.max(0, count));

  res.setHeader('Content-Type', 'application/scim+json');
  res.json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults,
    startIndex,
    itemsPerPage: items.length,
    Resources: items.map(toScimUser)
  });
});

usersRouter.get('/:id', async (req, res) => {
  if (!requireBearer(req, res)) return;
  const user = await ScimUser.findById(req.params.id);
  if (!user) {
    return res.status(404).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '404',
      detail: 'User not found'
    });
  }
  res.setHeader('Content-Type', 'application/scim+json');
  res.json(toScimUser(user));
});

usersRouter.post('/', async (req, res) => {
  if (!requireBearer(req, res)) return;
  const body = req.body || {};
  const userName = body.userName || body.emails?.[0]?.value;
  const name = body.name?.formatted || body.displayName || userName;
  const password = body.password || Math.random().toString(36).slice(2) + 'A1!';

  if (!userName) {
    return res.status(400).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '400',
      detail: 'userName or emails[0].value required'
    });
  }

  const existing = await ScimUser.findOne({ email: userName.toLowerCase() });
  if (existing) {
    return res.status(409).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '409',
      detail: 'User already exists'
    });
  }

  const doc = new ScimUser({
    email: userName.toLowerCase(),
    password,
    name: name || userName,
    isVerified: !!body.active,
    createdAt: new Date()
  });
  await doc.save();
  res.status(201).setHeader('Content-Type', 'application/scim+json');
  res.json(toScimUser(doc));
});

usersRouter.put('/:id', async (req, res) => {
  if (!requireBearer(req, res)) return;
  const body = req.body || {};
  const user = await ScimUser.findById(req.params.id);
  if (!user) {
    return res.status(404).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '404',
      detail: 'User not found'
    });
  }
  if (body.userName || body.emails?.[0]?.value) user.email = (body.userName || body.emails?.[0]?.value).toLowerCase();
  if (body.name?.formatted) user.name = body.name.formatted;
  if (typeof body.active === 'boolean') user.isVerified = body.active;
  if (body.password) user.password = body.password;
  await user.save();
  res.setHeader('Content-Type', 'application/scim+json');
  res.json(toScimUser(user));
});

usersRouter.patch('/:id', async (req, res) => {
  if (!requireBearer(req, res)) return;
  const body = req.body || {};
  const user = await ScimUser.findById(req.params.id);
  if (!user) {
    return res.status(404).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '404',
      detail: 'User not found'
    });
  }
  // Support RFC7644 PATCH with operations
  if (Array.isArray(body.Operations)) {
    for (const op of body.Operations) {
      const opName = (op.op || op.operation || '').toLowerCase();
      const path = (op.path || '').toLowerCase();
      if (opName === 'replace') {
        const value = op.value ?? op.values ?? {};
        if (path === 'name.formatted' && typeof value === 'string') user.name = value;
        if (path === 'active' && typeof value === 'boolean') user.isVerified = value;
        if (path === 'emails' && Array.isArray(value) && value[0]?.value) user.email = String(value[0].value).toLowerCase();
        if (path === 'userName'.toLowerCase() && typeof value === 'string') user.email = value.toLowerCase();
        if (!path && typeof value === 'object') {
          if (value.name?.formatted) user.name = value.name.formatted;
          if (typeof value.active === 'boolean') user.isVerified = value.active;
          if (value.emails?.[0]?.value) user.email = String(value.emails[0].value).toLowerCase();
          if (value.userName) user.email = String(value.userName).toLowerCase();
        }
      }
      if (opName === 'add' && (path === 'emails' || path === 'emails[value eq "primary"')) {
        const value = op.value;
        if (Array.isArray(value) && value[0]?.value) user.email = String(value[0].value).toLowerCase();
      }
      if (opName === 'remove' && path.startsWith('emails')) {
        // ignore email removal to preserve unique identifier
      }
    }
  }
  await user.save();
  res.setHeader('Content-Type', 'application/scim+json');
  res.json(toScimUser(user));
});

usersRouter.delete('/:id', async (req, res) => {
  if (!requireBearer(req, res)) return;
  const user = await ScimUser.findByIdAndDelete(req.params.id);
  if (!user) {
    return res.status(404).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '404',
      detail: 'User not found'
    });
  }
  res.status(204).send();
});


