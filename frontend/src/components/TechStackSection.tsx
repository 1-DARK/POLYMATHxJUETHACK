import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Code2, 
  Terminal, 
  Smartphone, 
  Monitor, 
  Shield, 
  Database,
  Cpu,
  Network,
  FileCode,
  Key,
  Lock
} from "lucide-react";

const techStack = {
  frontend: [
    { name: "Qt/PyQt", icon: Monitor, description: "Cross-platform native UI framework" },
    { name: "Python", icon: Code2, description: "Core application logic and scripting" },
    { name: "JSON/PDF", icon: FileCode, description: "Report generation and data export" }
  ],
  backend: [
    { name: "OpenSSL", icon: Key, description: "RSA certificate signing and validation" },
    { name: "SQLite", icon: Database, description: "Secure audit log storage" },
    { name: "REST API", icon: Network, description: "Enterprise system integration" }
  ],
  security: [
    { name: "RSA-2048", icon: Shield, description: "Digital certificate encryption" },
    { name: "SHA-256", icon: Cpu, description: "Cryptographic hashing" },
    { name: "AES-256", icon: Key, description: "Data encryption at rest" }
  ],
  platforms: [
    { 
      name: "Windows", 
      icon: Monitor, 
      tools: ["DiskPart", "SDelete", "PowerShell"],
      description: "Native Windows wiping utilities"
    },
    { 
      name: "Linux", 
      icon: Terminal, 
      tools: ["hdparm", "nvme-cli", "dd", "shred", "nwipe"],
      description: "Advanced Linux disk management"
    },
    { 
      name: "Android", 
      icon: Smartphone, 
      tools: ["Factory Reset API", "ADB/Fastboot", "Secure Erase"],
      description: "Mobile device secure wiping"
    }
  ]
};

export const TechStackSection = () => {
  return (
    <section className="py-24 px-4">
      <div className="max-w-7xl mx-auto">
        {/* Section Header */}
        <div className="text-center mb-16">
          <Badge className="mb-4 bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30">
            Technical Architecture
          </Badge>
          <h2 className="text-4xl md:text-5xl font-bold mb-6">
            Robust Tech Stack
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Built with enterprise-grade technologies and security frameworks for reliable, scalable data wiping operations.
          </p>
        </div>

        {/* Tech Stack Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-16">
          {/* Frontend Technologies */}
          <Card className="bg-card/50 backdrop-blur-sm border-border/50 hover:border-cyber-blue/30 transition-all duration-300">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <div className="p-2 bg-cyber-blue/20 rounded-lg">
                  <Code2 className="w-6 h-6 text-cyber-blue" />
                </div>
                Frontend & UI
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {techStack.frontend.map((tech) => (
                <div key={tech.name} className="flex items-start gap-3 p-3 rounded-lg bg-muted/30">
                  <tech.icon className="w-5 h-5 text-cyber-blue mt-1" />
                  <div>
                    <div className="font-semibold">{tech.name}</div>
                    <div className="text-sm text-muted-foreground">{tech.description}</div>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Backend Technologies */}
          <Card className="bg-card/50 backdrop-blur-sm border-border/50 hover:border-cyber-purple/30 transition-all duration-300">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <div className="p-2 bg-cyber-purple/20 rounded-lg">
                  <Database className="w-6 h-6 text-cyber-purple" />
                </div>
                Backend & Security
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {techStack.backend.map((tech) => (
                <div key={tech.name} className="flex items-start gap-3 p-3 rounded-lg bg-muted/30">
                  <tech.icon className="w-5 h-5 text-cyber-purple mt-1" />
                  <div>
                    <div className="font-semibold">{tech.name}</div>
                    <div className="text-sm text-muted-foreground">{tech.description}</div>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Security Framework */}
          <Card className="bg-card/50 backdrop-blur-sm border-border/50 hover:border-cyber-cyan/30 transition-all duration-300">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <div className="p-2 bg-cyber-cyan/20 rounded-lg">
                  <Shield className="w-6 h-6 text-cyber-cyan" />
                </div>
                Security Framework
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {techStack.security.map((tech) => (
                <div key={tech.name} className="flex items-start gap-3 p-3 rounded-lg bg-muted/30">
                  <tech.icon className="w-5 h-5 text-cyber-cyan mt-1" />
                  <div>
                    <div className="font-semibold">{tech.name}</div>
                    <div className="text-sm text-muted-foreground">{tech.description}</div>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Platform Support */}
          <Card className="bg-card/50 backdrop-blur-sm border-border/50 hover:border-success/30 transition-all duration-300">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <div className="p-2 bg-success/20 rounded-lg">
                  <Cpu className="w-6 h-6 text-success" />
                </div>
                Platform Support
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {techStack.platforms.map((platform) => (
                <div key={platform.name} className="p-4 rounded-lg bg-muted/30 border border-border/20">
                  <div className="flex items-start gap-3 mb-3">
                    <platform.icon className="w-5 h-5 text-success mt-1" />
                    <div>
                      <div className="font-semibold">{platform.name}</div>
                      <div className="text-sm text-muted-foreground">{platform.description}</div>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {platform.tools.map((tool) => (
                      <Badge key={tool} variant="secondary" className="text-xs">
                        {tool}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Architecture Diagram Placeholder */}
        <Card className="bg-gradient-to-r from-cyber-blue/10 to-cyber-purple/10 border-cyber-blue/20">
          <CardContent className="p-8 text-center">
            <div className="mb-4">
              <Network className="w-16 h-16 text-cyber-blue mx-auto mb-4" />
              <h3 className="text-2xl font-bold mb-2">System Architecture</h3>
              <p className="text-muted-foreground">
                Modular design with clear separation between UI, wiping engine, certificate generation, and verification components.
              </p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-8">
              <div className="p-4 bg-background/50 rounded-lg border border-border/20">
                <div className="font-semibold text-cyber-blue">UI Layer</div>
                <div className="text-sm text-muted-foreground">Qt/PyQt Interface</div>
              </div>
              <div className="p-4 bg-background/50 rounded-lg border border-border/20">
                <div className="font-semibold text-cyber-purple">Engine Layer</div>
                <div className="text-sm text-muted-foreground">Wiping Operations</div>
              </div>
              <div className="p-4 bg-background/50 rounded-lg border border-border/20">
                <div className="font-semibold text-cyber-cyan">Security Layer</div>
                <div className="text-sm text-muted-foreground">Certificate Generation</div>
              </div>
              <div className="p-4 bg-background/50 rounded-lg border border-border/20">
                <div className="font-semibold text-success">Verification</div>
                <div className="text-sm text-muted-foreground">Audit & Compliance</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  );
};