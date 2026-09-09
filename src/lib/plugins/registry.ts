import { CheckPlugin } from './types';
import { tlsCertCheckPlugin } from './tlsCertCheck';
import { httpHeadersCheckPlugin } from './httpHeadersCheck';
import { techFingerprintCheckPlugin } from './techFingerprintCheck';
import { portScanCheckPlugin } from './portScanCheck';
import { cveCorrelationCheckPlugin } from './cveCorrelationCheck';
import { emailSecurityCheckPlugin } from './emailSecurityCheck';
import { dnsHealthCheckPlugin } from './dnsHealthCheck';
import { subdomainTakeoverCheckPlugin } from './subdomainTakeoverCheck';
import { sensitivePathCheckPlugin } from './sensitivePathCheck';
import { cloudBucketCheckPlugin } from './cloudBucketCheck';
import { webHygieneCheckPlugin } from './webHygieneCheck';
import { cmsCheckPlugin } from './cmsCheck';
import { databaseMisconfigCheckPlugin } from './databaseMisconfigCheck';
import { smtpRelayCheckPlugin } from './smtpRelayCheck';
import { breachExposureCheckPlugin } from './breachExposureCheck';
import { githubSecretCheckPlugin } from './githubSecretCheck';
import { pasteSecretCheckPlugin } from './pasteSecretCheck';

export class PluginRegistry {
  private plugins: Map<string, CheckPlugin> = new Map();

  constructor() {
    // Core exposure check plugins
    this.register(tlsCertCheckPlugin);
    this.register(httpHeadersCheckPlugin);
    this.register(techFingerprintCheckPlugin);
    this.register(portScanCheckPlugin);
    this.register(cveCorrelationCheckPlugin);

    // Wave 1: Zero-Cost Feature Expansion plugins
    this.register(emailSecurityCheckPlugin);
    this.register(dnsHealthCheckPlugin);
    this.register(subdomainTakeoverCheckPlugin);
    this.register(sensitivePathCheckPlugin);

    // Wave 2: Zero-Cost Feature Expansion plugins
    this.register(cloudBucketCheckPlugin);
    this.register(webHygieneCheckPlugin);
    this.register(cmsCheckPlugin);

    // Wave 3: Zero-Cost Feature Expansion plugins
    this.register(databaseMisconfigCheckPlugin);
    this.register(smtpRelayCheckPlugin);

    // Wave 4: Zero-Cost Feature Expansion plugins
    this.register(breachExposureCheckPlugin);
    this.register(githubSecretCheckPlugin);
    this.register(pasteSecretCheckPlugin);
  }

  register(plugin: CheckPlugin): void {
    this.plugins.set(plugin.id, plugin);
  }

  unregister(pluginId: string): void {
    this.plugins.delete(pluginId);
  }

  getPlugin(id: string): CheckPlugin | undefined {
    return this.plugins.get(id);
  }

  getAllPlugins(): CheckPlugin[] {
    return Array.from(this.plugins.values());
  }

  getApplicablePlugins(asset: { fqdn: string; type: string }): CheckPlugin[] {
    return this.getAllPlugins().filter((p) => {
      try {
        return p.appliesTo(asset);
      } catch {
        return false;
      }
    });
  }
}

export const pluginRegistry = new PluginRegistry();
