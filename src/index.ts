import { ClientOptions, Cloudflare } from 'cloudflare';
import { AAAARecord, ARecord } from 'cloudflare/src/resources/dns/records.js';
type AddressableRecord = AAAARecord | ARecord;

class HttpError extends Error {
  constructor(public statusCode: number, message: string) {
    super(message);
    this.name = 'HttpError';
  }
}

function constructClientOptions(request: Request): ClientOptions {
  const authorization = request.headers.get('Authorization');
  if (!authorization) {
    throw new HttpError(401, 'API token missing.');
  }
  const [, data] = authorization.split(' ');
  const decoded = atob(data);
  const index = decoded.indexOf(':');

  if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
    throw new HttpError(401, 'Invalid API key or token.');
  }

  return {
    apiEmail: decoded.substring(0, index),
    apiToken: decoded.substring(index + 1),
  };
}

// Modified function: always use the client IP from Cloudflare.
function constructDNSRecord(request: Request): AddressableRecord {
  const url = new URL(request.url);
  const hostname = url.searchParams.get('hostname');
  
  if (!hostname) {
    throw new HttpError(422, 'The "hostname" parameter is required and cannot be empty.');
  }
  
  // Always extract the client IP from Cloudflare's context.
  const ip = request.cf?.connectingIp || request.headers.get('CF-Connecting-IP');
  if (!ip) {
    throw new HttpError(500, 'Unable to determine the client IP address.');
  }
  
  return {
    content: ip,
    name: hostname,
    type: ip.includes('.') ? 'A' : 'AAAA',
    ttl: 1,
  };
}

async function update(clientOptions: ClientOptions, newRecord: AddressableRecord): Promise<Response> {
  const cloudflare = new Cloudflare(clientOptions);

  const tokenStatus = (await cloudflare.user.tokens.verify()).status;
  if (tokenStatus !== 'active') {
    throw new HttpError(401, 'This API Token is ' + tokenStatus);
  }

  const zones = (await cloudflare.zones.list()).result;
  if (zones.length > 1) {
    throw new HttpError(400, 'More than one zone was found! You must supply an API Token scoped to a single zone.');
  } else if (zones.length === 0) {
    throw new HttpError(400, 'No zones found! You must supply an API Token scoped to a single zone.');
  }

  const zone = zones[0];

  const records = (
    await cloudflare.dns.records.list({
      zone_id: zone.id,
      name: newRecord.name as any,
      type: newRecord.type,
    })
  ).result;

  if (records.length > 1) {
    throw new HttpError(400, 'More than one matching record found!');
  } else if (records.length === 0 || records[0].id === undefined) {
    throw new HttpError(400, 'No record found! You must first manually create the record.');
  }

  // Preserve properties from the existing record.
  const currentRecord = records[0] as AddressableRecord;
  const proxied = currentRecord.proxied ?? false;
  const comment = currentRecord.comment;

  await cloudflare.dns.records.update(records[0].id, {
    content: newRecord.content,
    zone_id: zone.id,
    name: newRecord.name as any,
    type: newRecord.type,
    proxied,
    comment,
  });

  console.log('DNS record for ' + newRecord.name + '(' + newRecord.type + ') updated successfully to ' + newRecord.content);

  return new Response('OK', { status: 200 });
}

export default {
  async fetch(request): Promise<Response> {
    console.log('Requester IP: ' + request.headers.get('CF-Connecting-IP'));
    console.log(request.method + ': ' + request.url);
    console.log('Body: ' + (await request.text()));

    try {
      // Build client options and the DNS record using the modified functions.
      const clientOptions = constructClientOptions(request);
      const record = constructDNSRecord(request);

      // Update the DNS record.
      return await update(clientOptions, record);
    } catch (error) {
      if (error instanceof HttpError) {
        console.log('Error updating DNS record: ' + error.message);
        return new Response(error.message, { status: error.statusCode });
      } else {
        console.log('Error updating DNS record: ' + error);
        return new Response('Internal Server Error', { status: 500 });
      }
    }
  },
} satisfies ExportedHandler<Env>;
