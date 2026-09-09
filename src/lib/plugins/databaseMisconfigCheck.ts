import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';
import { safeTcpConnect as defaultSafeTcpConnect } from '@/lib/security';

/**
 * Builds a standard MongoDB OP_QUERY packet querying `{ isMaster: 1 }` on `admin.$cmd`.
 * Total packet size: 57 bytes.
 */
function buildMongoIsMasterPacket(): Buffer {
  const collectionName = 'admin.$cmd\0';
  // BSON for { isMaster: 1 }
  // 4 bytes doc length: 19
  // 1 byte type int32 (0x10)
  // 9 bytes "isMaster\0"
  // 4 bytes value 1 (0x01, 0x00, 0x00, 0x00)
  // 1 byte null terminator (0x00)
  const bsonDoc = Buffer.from([
    0x13, 0x00, 0x00, 0x00, // 19 bytes length
    0x10,                   // int32
    0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, // "isMaster\0"
    0x01, 0x00, 0x00, 0x00, // 1
    0x00                    // terminator
  ]);

  const headerLength = 16;
  const bodyLength = 4 + Buffer.byteLength(collectionName) + 4 + 4 + bsonDoc.length;
  const totalLength = headerLength + bodyLength;

  const packet = Buffer.alloc(totalLength);
  let offset = 0;

  // Header
  packet.writeInt32LE(totalLength, offset); offset += 4; // messageLength
  packet.writeInt32LE(1, offset); offset += 4;           // requestID
  packet.writeInt32LE(0, offset); offset += 4;           // responseTo
  packet.writeInt32LE(2004, offset); offset += 4;        // opCode: OP_QUERY (2004)

  // OP_QUERY Body
  packet.writeInt32LE(0, offset); offset += 4;           // flags: 0
  packet.write(collectionName, offset, 'ascii'); offset += Buffer.byteLength(collectionName);
  packet.writeInt32LE(0, offset); offset += 4;           // numberToSkip: 0
  packet.writeInt32LE(-1, offset); offset += 4;          // numberToReturn: -1
  bsonDoc.copy(packet, offset);

  return packet;
}

export const databaseMisconfigCheckPlugin: CheckPlugin = {
  id: 'database-misconfig-check',
  name: 'Database & In-Memory Store Exposure Analyzer',
  category: 'EXPOSED_SERVICES',
  defaultConfidence: 'CONFIRMED',

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];
    const host = asset.fqdn.toLowerCase().trim();

    const probedServices: Record<string, any> = {};
    const tcpConnect = ctx.safeTcpConnect || defaultSafeTcpConnect;

    // ========================================================
    // 1. Unauthenticated Redis Detection (Port 6379)
    // ========================================================
    try {
      const redisSession = await tcpConnect(host, 6379, { timeoutMs: 2500 });
      try {
        await redisSession.write('PING\r\n');
        const responseBuf = await redisSession.read(2000);
        const respText = responseBuf.toString('utf-8');

        if (respText.startsWith('+PONG')) {
          findings.push({
            category: 'EXPOSED_SERVICES',
            findingCode: 'DB-REDIS-UNAUTHENTICATED',
            title: 'Unauthenticated Redis In-Memory Database Exposed (Port 6379)',
            description: `Redis server on ${host}:6379 answered a PING command with "+PONG" without requiring authentication. Any unauthenticated attacker on the public internet can read keys, dump memory, or execute remote commands.`,
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            remediationGuidance: 'Enable "requirepass <strong-password>" in redis.conf, bind Redis strictly to localhost (127.0.0.1) or internal VPC interfaces, and block port 6379 at your external firewall.',
          });
          probedServices['redis'] = { exposed: true, authenticated: false, response: '+PONG' };
        } else if (respText.includes('NOAUTH')) {
          probedServices['redis'] = { exposed: true, authenticated: true, response: 'NOAUTH' };
        }
      } finally {
        redisSession.close();
      }
    } catch {
      probedServices['redis'] = { exposed: false };
    }

    // ========================================================
    // 2. Unauthenticated Elasticsearch Detection (Port 9200)
    // ========================================================
    try {
      const esRes = await ctx.safeFetch(`http://${host}:9200/`, {
        method: 'GET',
        timeoutMs: 2500,
        headers: { Accept: 'application/json' },
      });

      if (esRes.status === 200) {
        try {
          const esJson = await esRes.json();
          if (esJson && (esJson.cluster_name || esJson.tagline === 'You Know, for Search')) {
            const clusterName = esJson.cluster_name || 'default-cluster';
            const versionStr = esJson.version?.number ? ` (v${esJson.version.number})` : '';

            findings.push({
              category: 'EXPOSED_SERVICES',
              findingCode: 'DB-ELASTICSEARCH-UNAUTHENTICATED',
              title: `Unauthenticated Elasticsearch Cluster Exposed: ${clusterName}`,
              description: `Elasticsearch cluster "${clusterName}"${versionStr} on ${host}:9200 answered an unauthenticated HTTP GET request with full cluster metadata. All indexes, documents, and search queries are publicly accessible without authentication.`,
              severity: 'CRITICAL',
              confidence: 'CONFIRMED',
              remediationGuidance: 'Enable Elastic Stack Security (xpack.security.enabled: true), set passwords for built-in users, and place Elasticsearch behind an API gateway or internal network.',
            });
            probedServices['elasticsearch'] = { exposed: true, authenticated: false, clusterName, version: esJson.version?.number };
          }
        } catch {}
      } else if (esRes.status === 401) {
        probedServices['elasticsearch'] = { exposed: true, authenticated: true, status: 401 };
      }
    } catch {
      probedServices['elasticsearch'] = { exposed: false };
    }

    // ========================================================
    // 3. Unauthenticated MongoDB Detection (Port 27017)
    // ========================================================
    try {
      const mongoSession = await tcpConnect(host, 27017, { timeoutMs: 2500 });
      try {
        const queryPacket = buildMongoIsMasterPacket();
        await mongoSession.write(queryPacket);
        const responseBuf = await mongoSession.read(2000);
        const respStr = responseBuf.toString('utf-8');

        // BSON response to isMaster contains "ismaster", "maxBsonObjectSize", or "ok"
        const isMongoResponse =
          responseBuf.length >= 36 &&
          (respStr.includes('ismaster') || respStr.includes('isWritablePrimary') || respStr.includes('maxBsonObjectSize'));

        if (isMongoResponse) {
          findings.push({
            category: 'EXPOSED_SERVICES',
            findingCode: 'DB-MONGODB-UNAUTHENTICATED',
            title: 'Unauthenticated MongoDB Database Exposed (Port 27017)',
            description: `MongoDB database on ${host}:27017 answered remote wire protocol commands without requiring authentication. Any unauthorized party can connect, list databases, and access stored documents.`,
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            remediationGuidance: 'Enable access control in mongod.conf (security.authorization: "enabled"), bind MongoDB strictly to private interfaces (bindIp: 127.0.0.1), and block external access to port 27017.',
          });
          probedServices['mongodb'] = { exposed: true, authenticated: false };
        }
      } finally {
        mongoSession.close();
      }
    } catch {
      probedServices['mongodb'] = { exposed: false };
    }

    evidence.push({
      checkType: 'SERVICE_BANNER',
      rawObservation: {
        host,
        probedServices,
        scannedAt: new Date().toISOString(),
      },
    });

    return {
      status: 'COMPLETED',
      evidence,
      findings,
      durationMs: Date.now() - startTime,
    };
  },
};
