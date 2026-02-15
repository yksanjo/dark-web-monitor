const axios = require('axios');
const cheerio = require('cheerio');
const { detectCredentials, scanForDomains } = require('./scanner');

// Public breach databases and leak databases to monitor
const BREACH_SOURCES = [
  {
    name: 'Have I Been Pwned (checks)',
    url: 'https://haveibeenpwned.com/',
    type: 'landing'
  },
  {
    name: 'Dehashed Search',
    url: 'https://dehashed.com/search?q={domain}',
    type: 'search'
  },
  {
    name: 'BugMeNot (domain search)',
    url: 'https://bugmenot.com/view/{domain}',
    type: 'search'
  }
];

class Monitor {
  constructor(domains, options = {}) {
    this.domains = domains;
    this.interval = options.interval || 30 * 60 * 1000;
    this.verbose = options.verbose || false;
    this.once = options.once || false;
    this.isRunning = false;
    this.lastCheck = null;
    this.findings = [];
  }

  async start() {
    this.isRunning = true;
    console.log('🚀 Starting dark web monitoring...\n');

    await this.check();

    if (this.once) {
      console.log('\n✅ Single scan completed');
      this.printSummary();
      return;
    }

    console.log(`\n⏳ Continuous monitoring active. Checking every ${this.interval / 60000} minutes...`);
    console.log('Press Ctrl+C to stop.\n');

    this.intervalId = setInterval(async () => {
      await this.check();
    }, this.interval);
  }

  stop() {
    this.isRunning = false;
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }
  }

  async check() {
    this.lastCheck = new Date();
    console.log(`\n[${this.lastCheck.toISOString()}] Checking dark web sources...`);

    let totalScanned = 0;
    let threatsFound = 0;

    // Monitor breach databases
    try {
      if (this.verbose) {
        console.log('  📂 Checking breach databases...');
      }
      const breachResults = await this.checkBreachDatabases();
      totalScanned += breachResults.length;
      
      for (const result of breachResults) {
        if (result.findings.length > 0) {
          threatsFound += result.findings.length;
          this.findings.push(...result.findings);
          this.alert(result.findings);
        }
      }
    } catch (error) {
      console.error(`  ❌ Error checking breach databases: ${error.message}`);
    }

    // Monitor leak sites
    try {
      if (this.verbose) {
        console.log('  📂 Checking leak sites...');
      }
      const leakResults = await this.checkLeakSites();
      totalScanned += leakResults.length;
      
      for (const result of leakResults) {
        if (result.findings.length > 0) {
          threatsFound += result.findings.length;
          this.findings.push(...result.findings);
          this.alert(result.findings);
        }
      }
    } catch (error) {
      console.error(`  ❌ Error checking leak sites: ${error.message}`);
    }

    // Monitor onion links
    try {
      if (this.verbose) {
        console.log('  📂 Checking dark web link directories...');
      }
      const linkResults = await this.checkDarkWebLinks();
      totalScanned += linkResults.length;
      
      for (const result of linkResults) {
        if (result.findings.length > 0) {
          threatsFound += result.findings.length;
          this.findings.push(...result.findings);
          this.alert(result.findings);
        }
      }
    } catch (error) {
      console.error(`  ❌ Error checking dark web links: ${error.message}`);
    }

    console.log(`  ✅ Scanned ${totalScanned} sources, found ${threatsFound} potential leak(s)`);
  }

  async checkBreachDatabases() {
    const results = [];
    
    // Note: These are public-facing services that may require API keys or have rate limits
    // This demonstrates the concept - real implementation would need proper API access
    
    const sources = [
      {
        name: 'scylla.sh',
        url: 'https://scylla.sh/search?q=',
        type: 'html'
      },
      {
        name: 'leakpeek',
        url: 'https://leakpeek.com/search?search=',
        type: 'html'
      }
    ];

    for (const source of sources) {
      for (const domain of this.domains) {
        try {
          const url = source.url + encodeURIComponent(domain);
          const response = await axios.get(url, {
            timeout: 10000,
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
          });

          const findings = this.analyzeContent(response.data, domain, source.name);
          if (findings.length > 0) {
            results.push({
              source: source.name,
              domain: domain,
              findings: findings
            });
          }
        } catch (error) {
          if (this.verbose) {
            console.error(`    ${source.name} error: ${error.message}`);
          }
        }
      }
    }

    return results;
  }

  async checkLeakSites() {
    const results = [];
    
    // Monitor paste-like sites that may contain leaked data
    const sources = [
      {
        name: 'PrivateBin',
        url: 'https://privatebin.net/',
        type: 'landing'
      },
      {
        name: '0bin',
        url: 'https://0bin.net/',
        type: 'landing'
      }
    ];

    for (const source of sources) {
      try {
        const response = await axios.get(source.url, {
          timeout: 10000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        });

        const findings = this.analyzeContent(response.data, '', source.name);
        if (findings.length > 0) {
          results.push({
            source: source.name,
            domain: 'multiple',
            findings: findings
          });
        }
      } catch (error) {
        if (this.verbose) {
          console.error(`    ${source.name} error: ${error.message}`);
        }
      }
    }

    return results;
  }

  async checkDarkWebLinks() {
    const results = [];
    
    // Check onion link directories (safe, public sources)
    const sources = [
      {
        name: 'darkwebnews onion directory',
        url: 'https://www.darkwebnews.com/onions/',
        type: 'directory'
      },
      {
        name: 'darknetstats',
        url: 'https://dnstats.net/',
        type: 'directory'
      }
    ];

    for (const source of sources) {
      try {
        const response = await axios.get(source.url, {
          timeout: 10000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        });

        const content = response.data;
        
        // Check if any monitored domains are mentioned
        for (const domain of this.domains) {
          if (content.toLowerCase().includes(domain.toLowerCase())) {
            const findings = [{
              timestamp: new Date().toISOString(),
              source: source.name,
              type: 'onion_directory',
              url: source.url,
              domain: domain,
              matchedDomains: [domain],
              credentials: [],
              snippet: `Domain ${domain} found in ${source.name}`
            }];
            
            results.push({
              source: source.name,
              domain: domain,
              findings: findings
            });
          }
        }
      } catch (error) {
        if (this.verbose) {
          console.error(`    ${source.name} error: ${error.message}`);
        }
      }
    }

    return results;
  }

  analyzeContent(content, domain, source) {
    const findings = [];

    try {
      // Check for domain matches
      const domainList = domain ? [domain] : this.domains;
      const domainMatches = scanForDomains(content, domainList);
      
      if (domainMatches.length > 0) {
        const credentials = detectCredentials(content);
        
        if (credentials.length > 0) {
          findings.push({
            timestamp: new Date().toISOString(),
            source: source,
            type: 'breach_check',
            url: '',
            matchedDomains: domainMatches,
            credentials: credentials,
            snippet: content.substring(0, 200)
          });
        }
      }
    } catch (error) {
      // Silently ignore
    }

    return findings;
  }

  alert(findings) {
    for (const finding of findings) {
      console.log('\n🚨 ALERT: Potential Credential Leak Detected!');
      console.log('='.repeat(50));
      console.log(`Source: ${finding.source}`);
      console.log(`Type: ${finding.type || 'unknown'}`);
      console.log(`URL: ${finding.url || 'N/A'}`);
      console.log(`Matched Domains: ${finding.matchedDomains.join(', ')}`);
      if (finding.credentials.length > 0) {
        console.log(`Credential Types: ${finding.credentials.join(', ')}`);
      }
      if (finding.snippet) {
        console.log(`\nSnippet: ${finding.snippet}...`);
      }
      console.log('='.repeat(50));
    }
  }

  printSummary() {
    console.log('\n📊 Summary');
    console.log('='.repeat(30));
    console.log(`Total findings: ${this.findings.length}`);
    
    if (this.findings.length > 0) {
      console.log('\nDetails:');
      for (const finding of this.findings) {
        console.log(`  - [${finding.timestamp}] ${finding.source}: ${finding.matchedDomains.join(', ')}`);
      }
    }
  }
}

module.exports = Monitor;
