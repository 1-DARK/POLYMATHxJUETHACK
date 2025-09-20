import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Shield, Menu, X, Github, ExternalLink } from "lucide-react";
import { useState } from "react";

export const Navigation = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-background/80 backdrop-blur-md border-b border-border/20">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-r from-cyber-blue/20 to-cyber-purple/20 rounded-lg border border-cyber-blue/30">
              <Shield className="w-6 h-6 text-cyber-blue" />
            </div>
            <div>
              <div className="font-bold text-lg">SecureWipe Pro</div>
              <Badge className="text-xs bg-cyber-blue/20 text-cyber-blue border-cyber-blue/30">
                Team Polymath
              </Badge>
            </div>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            <a href="#features" className="text-foreground hover:text-cyber-blue transition-colors">
              Features
            </a>
            <a href="#process" className="text-foreground hover:text-cyber-blue transition-colors">
              Process
            </a>
            <a href="#tech" className="text-foreground hover:text-cyber-blue transition-colors">
              Technology
            </a>
            <a href="#demo" className="text-foreground hover:text-cyber-blue transition-colors">
              Demo
            </a>
          </div>

          {/* Desktop Actions */}
          <div className="hidden md:flex items-center gap-4">
            <Button 
              variant="outline" 
              size="sm" 
              className="border-cyber-blue/50 text-cyber-blue hover:bg-cyber-blue/10"
            >
              <Github className="w-4 h-4 mr-2" />
              GitHub
            </Button>
            <Button 
              size="sm" 
              className="bg-gradient-to-r from-cyber-blue to-cyber-purple hover:from-cyber-blue/90 hover:to-cyber-purple/90 text-white"
            >
              Try Now
              <ExternalLink className="w-4 h-4 ml-2" />
            </Button>
          </div>

          {/* Mobile Menu Button */}
          <Button
            variant="ghost"
            size="sm"
            className="md:hidden"
            onClick={() => setIsMenuOpen(!isMenuOpen)}
          >
            {isMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </Button>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <div className="md:hidden border-t border-border/20 py-4">
            <div className="flex flex-col space-y-4">
              <a 
                href="#features" 
                className="text-foreground hover:text-cyber-blue transition-colors"
                onClick={() => setIsMenuOpen(false)}
              >
                Features
              </a>
              <a 
                href="#process" 
                className="text-foreground hover:text-cyber-blue transition-colors"
                onClick={() => setIsMenuOpen(false)}
              >
                Process
              </a>
              <a 
                href="#tech" 
                className="text-foreground hover:text-cyber-blue transition-colors"
                onClick={() => setIsMenuOpen(false)}
              >
                Technology
              </a>
              <a 
                href="#demo" 
                className="text-foreground hover:text-cyber-blue transition-colors"
                onClick={() => setIsMenuOpen(false)}
              >
                Demo
              </a>
              <div className="flex flex-col gap-2 pt-4 border-t border-border/20">
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="border-cyber-blue/50 text-cyber-blue hover:bg-cyber-blue/10 justify-center"
                >
                  <Github className="w-4 h-4 mr-2" />
                  GitHub
                </Button>
                <Button 
                  size="sm" 
                  className="bg-gradient-to-r from-cyber-blue to-cyber-purple hover:from-cyber-blue/90 hover:to-cyber-purple/90 text-white justify-center"
                >
                  Try Now
                  <ExternalLink className="w-4 h-4 ml-2" />
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </nav>
  );
};