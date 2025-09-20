import { Navigation } from "@/components/Navigation";
import { HeroSection } from "@/components/HeroSection";
import { ProcessSection } from "@/components/ProcessSection";
import { FeaturesSection } from "@/components/FeaturesSection";
import { TechStackSection } from "@/components/TechStackSection";
import { Footer } from "@/components/Footer";

const Index = () => {
  return (
    <div className="min-h-screen">
      <Navigation />
      <main>
        <HeroSection />
        <div id="process">
          <ProcessSection />
        </div>
        <div id="features">
          <FeaturesSection />
        </div>
        <div id="tech">
          <TechStackSection />
        </div>
      </main>
      <Footer />
    </div>
  );
};

export default Index;
