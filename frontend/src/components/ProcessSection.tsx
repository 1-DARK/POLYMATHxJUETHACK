import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Search, Trash2, CheckCircle, Award, ArrowRight } from "lucide-react";

const processSteps = [
  {
    step: 1,
    title: "Device Scan",
    description: "Detect and scan devices across Windows, Linux, and Android platforms with comprehensive hardware analysis.",
    icon: Search,
    color: "cyber-blue",
    features: ["Cross-platform detection", "Hardware inventory", "Hidden partition discovery"]
  },
  {
    step: 2,
    title: "Secure Wipe",
    description: "Military-grade data sanitization targeting HPA, DCO, and hidden SSD sectors with multiple overwrite passes.",
    icon: Trash2,
    color: "cyber-purple",
    features: ["Multiple overwrite passes", "Hidden area sanitization", "Real-time progress tracking"]
  },
  {
    step: 3,
    title: "Verification",
    description: "Comprehensive data erasure verification with integrity checks and forensic-level validation.",
    icon: CheckCircle,
    color: "cyber-cyan",
    features: ["Forensic validation", "Integrity verification", "Compliance reporting"]
  },
  {
    step: 4,
    title: "Certification",
    description: "Generate tamper-proof RSA-signed certificates with QR codes for third-party verification.",
    icon: Award,
    color: "success",
    features: ["RSA digital signatures", "QR code verification", "Audit trail generation"]
  }
];

export const ProcessSection = () => {
  return (
    <section className="py-24 px-4">
      <div className="max-w-7xl mx-auto">
        {/* Section Header */}
        <div className="text-center mb-16">
          <Badge className="mb-4 bg-cyber-blue/20 text-cyber-blue border-cyber-blue/30">
            Secure Process
          </Badge>
          <h2 className="text-4xl md:text-5xl font-bold mb-6">
            4-Step Security Process
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Our comprehensive approach ensures complete data destruction with verifiable proof and compliance certification.
          </p>
        </div>

        {/* Process Steps */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8 relative">
          {processSteps.map((step, index) => (
            <div key={step.step} className="relative">
              {/* Connection Line */}
              {index < processSteps.length - 1 && (
                <div className="hidden lg:block absolute top-1/2 -right-4 transform -translate-y-1/2 z-0">
                  <ArrowRight className="w-8 h-8 text-muted-foreground/30" />
                </div>
              )}
              
              {/* Step Card */}
              <Card className="relative z-10 bg-card/50 backdrop-blur-sm border-border/50 hover:border-cyber-blue/30 transition-all duration-300 hover:shadow-cyber h-full">
                <CardContent className="p-8">
                  {/* Step Number */}
                  <div className={`w-16 h-16 rounded-full bg-${step.color}/20 flex items-center justify-center mb-6 mx-auto border-2 border-${step.color}/30`}>
                    <step.icon className={`w-8 h-8 text-${step.color}`} />
                  </div>

                  {/* Step Info */}
                  <div className="text-center mb-6">
                    <Badge variant="secondary" className="mb-3">
                      Step {step.step}
                    </Badge>
                    <h3 className="text-2xl font-bold mb-3">{step.title}</h3>
                    <p className="text-muted-foreground leading-relaxed">
                      {step.description}
                    </p>
                  </div>

                  {/* Features */}
                  <ul className="space-y-2">
                    {step.features.map((feature) => (
                      <li key={feature} className="flex items-center gap-2 text-sm">
                        <div className={`w-2 h-2 rounded-full bg-${step.color}`} />
                        <span>{feature}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </div>
          ))}
        </div>

        {/* Bottom CTA */}
        <div className="text-center mt-16">
          <div className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-cyber-blue/10 to-cyber-purple/10 rounded-full border border-cyber-blue/20">
            <CheckCircle className="w-5 h-5 text-success" />
            <span className="font-medium">Certified compliance with international data protection standards</span>
          </div>
        </div>
      </div>
    </section>
  );
};