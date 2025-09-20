import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Shield, 
  Smartphone, 
  HardDrive, 
  QrCode, 
  FileCheck, 
  Zap, 
  Lock, 
  Globe, 
  Eye,
  Server,
  UserCheck,
  Download
} from "lucide-react";

const features = [
  {
    icon: Shield,
    title: "Tamper-Proof Certificates",
    description: "RSA-signed digital certificates that cannot be altered, providing immutable proof of data erasure.",
    category: "Security",
    highlight: true
  },
  {
    icon: Globe,
    title: "Cross-Platform Support",
    description: "Works seamlessly across Windows, Linux, and Android with native tools and bootable modes.",
    category: "Compatibility",
    highlight: true
  },
  {
    icon: HardDrive,
    title: "Hidden Area Wiping",
    description: "Sanitizes HPA, DCO, and hidden SSD sectors that standard tools often miss.",
    category: "Thoroughness",
    highlight: true
  },
  {
    icon: QrCode,
    title: "QR Code Verification",
    description: "Embedded QR codes enable instant third-party verification of erasure certificates.",
    category: "Verification"
  },
  {
    icon: FileCheck,
    title: "Detailed Audit Logs",
    description: "Comprehensive JSON and PDF reports with complete audit trails for compliance.",
    category: "Compliance"
  },
  {
    icon: Zap,
    title: "Real-Time Progress",
    description: "Live monitoring of wiping progress with detailed status updates and time estimates.",
    category: "Monitoring"
  },
  {
    icon: Lock,
    title: "Firmware Validation",
    description: "Advanced firmware-level process validation ensures complete data destruction.",
    category: "Security"
  },
  {
    icon: Smartphone,
    title: "Offline Bootable Mode",
    description: "ISO/USB bootable environments for air-gapped security and offline operations.",
    category: "Security"
  },
  {
    icon: Eye,
    title: "Integrity Verification",
    description: "Forensic-level verification ensures data is completely unrecoverable.",
    category: "Verification"
  },
  {
    icon: Server,
    title: "Enterprise Integration",
    description: "API support for integration with existing IT asset management systems.",
    category: "Integration"
  },
  {
    icon: UserCheck,
    title: "Third-Party Validation",
    description: "Independent verification tools for auditors and compliance officers.",
    category: "Compliance"
  },
  {
    icon: Download,
    title: "Multi-Format Export",
    description: "Export certificates and reports in multiple formats (PDF, JSON, XML).",
    category: "Flexibility"
  }
];

const categories = ["Security", "Compliance", "Verification", "Compatibility", "Thoroughness", "Monitoring", "Integration", "Flexibility"];

export const FeaturesSection = () => {
  return (
    <section className="py-24 px-4 bg-gradient-to-br from-background to-muted/20">
      <div className="max-w-7xl mx-auto">
        {/* Section Header */}
        <div className="text-center mb-16">
          <Badge className="mb-4 bg-cyber-purple/20 text-cyber-purple border-cyber-purple/30">
            Innovation Features
          </Badge>
          <h2 className="text-4xl md:text-5xl font-bold mb-6">
            Advanced Security Features
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Comprehensive data wiping solution with enterprise-grade security, compliance, and verification capabilities.
          </p>
        </div>

        {/* Feature Categories Filter */}
        <div className="flex flex-wrap justify-center gap-2 mb-12">
          {categories.map((category) => (
            <Badge 
              key={category}
              variant="secondary"
              className="cursor-pointer hover:bg-cyber-blue/20 hover:text-cyber-blue transition-colors"
            >
              {category}
            </Badge>
          ))}
        </div>

        {/* Features Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <Card 
              key={index}
              className={`group bg-card/50 backdrop-blur-sm border-border/50 hover:border-cyber-blue/30 transition-all duration-300 hover:shadow-cyber ${
                feature.highlight ? 'ring-2 ring-cyber-blue/20 shadow-glow' : ''
              }`}
            >
              <CardHeader className="pb-4">
                <div className="flex items-start justify-between">
                  <div className={`p-3 rounded-lg ${
                    feature.highlight 
                      ? 'bg-gradient-to-r from-cyber-blue/20 to-cyber-purple/20 border border-cyber-blue/30' 
                      : 'bg-muted/50'
                  }`}>
                    <feature.icon className={`w-6 h-6 ${
                      feature.highlight ? 'text-cyber-blue' : 'text-muted-foreground'
                    }`} />
                  </div>
                  <Badge 
                    variant="secondary" 
                    className="text-xs"
                  >
                    {feature.category}
                  </Badge>
                </div>
                <CardTitle className="text-xl group-hover:text-cyber-blue transition-colors">
                  {feature.title}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground leading-relaxed">
                  {feature.description}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Bottom Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mt-16 pt-16 border-t border-border/20">
          <div className="text-center">
            <div className="text-3xl font-bold text-cyber-blue mb-2">256-bit</div>
            <div className="text-sm text-muted-foreground">RSA Encryption</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-cyber-purple mb-2">35+</div>
            <div className="text-sm text-muted-foreground">Overwrite Passes</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-cyber-cyan mb-2">DoD 5220</div>
            <div className="text-sm text-muted-foreground">Compliant</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-success mb-2">ISO 27001</div>
            <div className="text-sm text-muted-foreground">Certified</div>
          </div>
        </div>
      </div>
    </section>
  );
};