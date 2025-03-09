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

  // The Authorization header is expected to be "Basic base64Encoded(user:token)"
  const [, data] = authorization.split(' ');
  const decoded = atob(data);
  const index = decoded.indexOf(':');

  if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
    throw new HttpError(401, 'Invalid API key or token format in Authorization header.');
  }

  return {
    apiEmail: decoded.substring(0, index),
    apiToken: decoded.substring(index + 1),
  };
}

/**
 * Always uses Cloudflare's IP (request.cf?.connectingIp) for the DNS record update,
 * but will still log the device's IP if provided in the query parameter (?ip=).
 */
function constructDNSRecord(request: Request): AddressableRecord {
  const url = new URL(request.url);

  // The device IP param that the UDM might send, e.g. ?ip=%i
  const deviceIpParam = url.searchParams.get('ip');
  // The mandatory hostname, e.g. ?hostname=%h
  const hostname = url.searchParams.get('hostname');

  // Enforce the presence of the hostname
  if (!hostname) {
    throw new HttpError(422, 'The "hostname" parameter is required and cannot be empty.');
  }

  // Always use the requester's IP from Cloudflare for the DNS record
  const finalIp = request.cf?.connectingIp || request.headers.get('CF-Connecting-IP');
  if (!finalIp) {
    throw new HttpError(500, 'Unable to determine the client IP address from Cloudflare.');
  }

  // Log or do anything you want with the device IP param, but do not use it in the DNS update
  console.log(`Ignoring device-supplied IP param: ${deviceIpParam}`);
  console.log(`Using CF-Connecting-IP instead: ${finalIp}`);

  return {
    content: finalIp,
    name: hostname,
    type: finalIp.includes('.') ? 'A' : 'AAAA',
    ttl: 1,
  };
}

async function update(clientOptions: ClientOptions, newRecord: AddressableRecord): Promise<Response> {
  const cloudflare = new Cloudflare(clientOptions);

  // Verify token status
  const tokenStatus = (await cloudflare.user.tokens.verify()).status;
  if (tokenStatus !== 'active') {
    throw new HttpError(401, 'This API Token is ' + tokenStatus);
  }

  // List zones
  const zones = (await cloudflare.zones.list()).result;
  if (zones.length > 1) {
    throw new HttpError(
      400,
      'More than one zone found! The API Token must be scoped to a single zone.'
    );
  } else if (zones.length === 0) {
    throw new HttpError(400, 'No zones found! The API Token must be scoped to at least one zone.');
  }

  const zone = zones[0];

  // Find existing DNS record for the requested hostname (newRecord.name)
  const records = (
    await cloudflare.dns.records.list({
      zone_id: zone.id,
      name: newRecord.name as any,
      type: newRecord.type,
    })
  ).result;

  if (records.length > 1) {
    throw new HttpError(400, 'More than one matching record found!');
  } else if (records.length === 0 || !records[0].id) {
    throw new HttpError(
      400,
      'No matching record found! You must manually create the record before updating.'
    );
  }

  // Preserve current "proxied" and "comment" properties
  const currentRecord = records[0] as AddressableRecord;
  const proxied = currentRecord.proxied ?? false;
  const comment = currentRecord.comment;

  // Update DNS record
  await cloudflare.dns.records.update(records[0].id, {
    content: newRecord.content,
    zone_id: zone.id,
    name: newRecord.name as any,
    type: newRecord.type,
    proxied,
    comment,
  });

  console.log(
    `DNS record for ${newRecord.name} (${newRecord.type}) updated successfully to ${newRecord.content}`
  );

  return new Response('OK', { status: 200 });
}

export default {
  async fetch(request: Request): Promise<Response> {
    // Basic logging for debugging
    console.log('Requester IP:', request.headers.get('CF-Connecting-IP'));
    console.log(`${request.method}: ${request.url}`);

    // If you want to see the request body for debugging
    const bodyText = await request.text();
    if (bodyText) {
      console.log('Request Body:', bodyText);
    }

    try {
      // 1. Parse your Cloudflare client options (API token, etc.)
      const clientOptions = constructClientOptions(request);

      // 2. Create the DNS record object, ignoring the device IP param
      const record = constructDNSRecord(request);

      // 3. Update the DNS record in Cloudflare
      return await update(clientOptions, record);
    } catch (error) {
      if (error instanceof HttpError) {
        console.log('Error updating DNS record:', error.message);
        return new Response(error.message, { status: error.statusCode });
      } else {
        console.log('Unexpected error:', error);
        return new Response('Internal Server Error', { status: 500 });
      }
    }
  },
} satisfies ExportedHandler<Env>;
