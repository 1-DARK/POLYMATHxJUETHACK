import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Shield, Github, Mail, ExternalLink, Award, Users } from "lucide-react";

export const Footer = () => {
  return (
    <footer className="bg-gradient-to-b from-background to-muted/20 border-t border-border/20 py-16">
      <div className="max-w-7xl mx-auto px-4">
        {/* Main Footer Content */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 mb-12">
          {/* Brand Section */}
          <div className="col-span-1 lg:col-span-2">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-gradient-to-r from-cyber-blue/20 to-cyber-purple/20 rounded-lg border border-cyber-blue/30">
                <Shield className="w-8 h-8 text-cyber-blue" />
              </div>
              <div>
                <div className="text-2xl font-bold">SecureWipe Pro</div>
                <Badge className="bg-cyber-blue/20 text-cyber-blue border-cyber-blue/30">
                  Team Polymath
                </Badge>
              </div>
            </div>
            <p className="text-muted-foreground leading-relaxed mb-6 max-w-md">
              Certified cross-platform secure data wiping solution with tamper-proof certificates. 
              Built for enterprise IT asset recycling and compliance.
            </p>
            <div className="flex items-center gap-4">
              <Button 
                variant="outline" 
                size="sm" 
                className="border-cyber-blue/50 text-cyber-blue hover:bg-cyber-blue/10"
              >
                <Github className="w-4 h-4 mr-2" />
                View Source
              </Button>
              <Button 
                variant="outline" 
                size="sm" 
                className="border-cyber-purple/50 text-cyber-purple hover:bg-cyber-purple/10"
              >
                <Mail className="w-4 h-4 mr-2" />
                Contact
              </Button>
            </div>
          </div>

          {/* Product Links */}
          <div>
            <h3 className="font-semibold mb-4">Product</h3>
            <ul className="space-y-3 text-sm">
              <li>
                <a href="#features" className="text-muted-foreground hover:text-cyber-blue transition-colors">
                  Features
                </a>
              </li>
              <li>
                <a href="#process" className="text-muted-foreground hover:text-cyber-blue transition-colors">
                  Security Process
                </a>
              </li>
              <li>
                <a href="#tech" className="text-muted-foreground hover:text-cyber-blue transition-colors">
                  Technology Stack
                </a>
              </li>
              <li>
                <a href="#demo" className="text-muted-foreground hover:text-cyber-blue transition-colors">
                  Live Demo
                </a>
              </li>
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h3 className="font-semibold mb-4">Resources</h3>
            <ul className="space-y-3 text-sm">
              <li>
                <a href="#" className="text-muted-foreground hover:text-cyber-blue transition-colors flex items-center gap-2">
                  Documentation
                  <ExternalLink className="w-3 h-3" />
                </a>
              </li>
              <li>
                <a href="#" className="text-muted-foreground hover:text-cyber-blue transition-colors flex items-center gap-2">
                  API Reference
                  <ExternalLink className="w-3 h-3" />
                </a>
              </li>
              <li>
                <a href="#" className="text-muted-foreground hover:text-cyber-blue transition-colors">
                  Compliance Guide
                </a>
              </li>
              <li>
                <a href="#" className="text-muted-foreground hover:text-cyber-blue transition-colors">
                  Support
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Awards & Recognition */}
        <div className="border-t border-border/20 pt-8 mb-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Award className="w-5 h-5 text-cyber-blue" />
                <span className="text-sm font-medium">JUETHack 2025 Project</span>
              </div>
              <div className="flex items-center gap-2">
                <Users className="w-5 h-5 text-cyber-purple" />
                <span className="text-sm font-medium">Team Polymath</span>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <Badge variant="secondary" className="text-xs">
                Problem Statement #25070
              </Badge>
              <Badge variant="secondary" className="text-xs">
                Miscellaneous Theme
              </Badge>
            </div>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="border-t border-border/20 pt-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-muted-foreground">
            <div className="flex items-center gap-4">
              <span>© 2025 Team Polymath. All rights reserved.</span>
              <span className="hidden md:inline">•</span>
              <span className="hidden md:inline">Secure Data Wiping Solution</span>
            </div>
            <div className="flex items-center gap-4">
              <a href="#" className="hover:text-cyber-blue transition-colors">Privacy Policy</a>
              <span>•</span>
              <a href="#" className="hover:text-cyber-blue transition-colors">Terms of Service</a>
              <span>•</span>
              <a href="#" className="hover:text-cyber-blue transition-colors">License</a>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};