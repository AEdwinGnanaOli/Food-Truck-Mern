import { useEffect } from "react";
import AOS from "aos";
import "aos/dist/aos.css";
import { useNavigate } from "react-router-dom";

function Index() {
  useEffect(() => {
    AOS.init({ duration: 1000 }); // You can customize the duration or other settings
  }, []);

  const navigate = useNavigate();

  return (
    <div className="index-header">
      {/* Start Hero Section */}
      <div className="hero" id="home">
        <div className="container mx-auto px-4 py-8">
          <div
            className="flex flex-col lg:flex-row justify-between items-center"
            data-aos="fade-up"
          >
            <div className="lg:w-1/2">
              <div className="intro-excerpt">
                <h1
                  className="text-4xl font-semibold mb-4 text-slate-50 text-center lg:text-left"
                  data-aos="fade-right"
                >
                  A Journey of Flavors
                </h1>
                <p
                  className="mb-6 text-base sm:text-xl text-slate-200 text-justify lg:text-left"
                  data-aos="fade-left"
                >
                  Food trucks have revolutionized dining, bringing gourmet meals
                  to every corner. This journey isn't just about the food. It's
                  about the stories and creativity behind each truck. With
                  vibrant designs and diverse menus, food trucks invite you to
                  explore new flavors and experiences.
                </p>
                <div className="flex lg:justify-start" data-aos="zoom-in">
                  <button
                    className="bg-green-500 text-white px-6 py-2 rounded-lg hover:bg-green-600 focus:outline-none focus:ring-2 focus:ring-green-400"
                    onClick={() => navigate("sign-in")}
                  >
                    Start Journey
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      {/* End Hero Section */}
    </div>
  );
}

export default Index;
