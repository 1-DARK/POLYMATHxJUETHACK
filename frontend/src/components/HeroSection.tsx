import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Shield, Zap, Award, ChevronRight } from "lucide-react";
import heroImage from "@/assets/hero-cyber-security.jpg";

export const HeroSection = () => {
  return (
    <section className="relative min-h-screen flex items-center justify-center px-4 overflow-hidden">
      {/* Background Image with Overlay */}
      <div 
        className="absolute inset-0 bg-cover bg-center bg-no-repeat"
        style={{ backgroundImage: `url(${heroImage})` }}
      >
        <div className="absolute inset-0 bg-gradient-to-br from-background/90 via-background/70 to-background/90" />
      </div>
      
      {/* Animated Background Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-32 h-32 bg-cyber-blue/10 rounded-full blur-xl animate-pulse" />
        <div className="absolute bottom-1/3 right-1/4 w-48 h-48 bg-cyber-purple/10 rounded-full blur-xl animate-pulse delay-1000" />
        <div className="absolute top-1/2 right-1/3 w-24 h-24 bg-cyber-cyan/10 rounded-full blur-xl animate-pulse delay-500" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto text-center">
        {/* Badge */}
        <Badge className="mb-6 bg-cyber-blue/20 text-cyber-blue border-cyber-blue/30 hover:bg-cyber-blue/30">
          <Shield className="w-4 h-4 mr-2" />
          JUETHack 2025 Winner
        </Badge>

        {/* Main Heading */}
        <h1 className="text-5xl md:text-7xl font-bold mb-6 bg-gradient-to-r from-foreground via-cyber-blue to-cyber-purple bg-clip-text text-transparent leading-tight">
          Certified Cross-Platform
          <br />
          <span className="cyber-glow">Secure Data Wiping</span>
        </h1>

        {/* Subheading */}
        <p className="text-xl md:text-2xl text-muted-foreground mb-8 max-w-3xl mx-auto leading-relaxed">
          Revolutionary IT asset recycling solution with tamper-proof certificates, 
          cross-platform compatibility, and military-grade data sanitization.
        </p>

        {/* Feature Highlights */}
        <div className="flex flex-wrap justify-center gap-4 mb-10">
          <div className="flex items-center gap-2 px-4 py-2 bg-card/50 backdrop-blur-sm rounded-full border border-border/50">
            <Shield className="w-5 h-5 text-cyber-blue" />
            <span className="text-sm font-medium">Tamper-Proof Certificates</span>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 bg-card/50 backdrop-blur-sm rounded-full border border-border/50">
            <Zap className="w-5 h-5 text-cyber-purple" />
            <span className="text-sm font-medium">Cross-Platform Support</span>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 bg-card/50 backdrop-blur-sm rounded-full border border-border/50">
            <Award className="w-5 h-5 text-cyber-cyan" />
            <span className="text-sm font-medium">Military-Grade Wiping</span>
          </div>
        </div>

        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Button 
            size="lg" 
            className="bg-gradient-to-r from-cyber-blue to-cyber-purple hover:from-cyber-blue/90 hover:to-cyber-purple/90 text-white font-semibold px-8 py-3 shadow-cyber"
          >
            Start Secure Wiping
            <ChevronRight className="w-5 h-5 ml-2" />
          </Button>
          <Button 
            variant="outline" 
            size="lg" 
            className="border-cyber-blue/50 text-cyber-blue hover:bg-cyber-blue/10 px-8 py-3"
          >
            View Documentation
          </Button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-8 mt-16 max-w-2xl mx-auto">
          <div className="text-center">
            <div className="text-3xl font-bold text-cyber-blue">100%</div>
            <div className="text-sm text-muted-foreground">Data Erasure</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-cyber-purple">3+</div>
            <div className="text-sm text-muted-foreground">Platforms</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-cyber-cyan">RSA</div>
            <div className="text-sm text-muted-foreground">Encryption</div>
          </div>
        </div>
      </div>
    </section>
  );
};