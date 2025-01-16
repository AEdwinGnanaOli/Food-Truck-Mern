import React, { useState, useEffect, useMemo } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { HiMenuAlt3, HiX } from "react-icons/hi";
import AOS from "aos";
import "aos/dist/aos.css";
import { useSelector, useDispatch } from "react-redux";
import useLogout from "../../hooks/useLogout";
import AccountCircleIcon from "@mui/icons-material/AccountCircle";
import useDialog from "../../hooks/useDialog";
import Profile from "../dialog/Profile";

const NAVIGATION_LINKS = [
  { name: "Home", href: "/" },
  { name: "Contact", href: "/contact" },
  { name: "About", href: "/about" }
];
const Header = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { userInfo, isLoggedIn } = useSelector((state) => state.user);
  const { isOpen, closeDialog, openDialog } = useDialog();

  const logout = useLogout();
  useEffect(() => {
    AOS.init({
      duration: 800,
      easing: "ease-in-out",
      offset: 50,
      once: true
    });
  }, []);

  const toggleMenu = () => setIsMenuOpen((prev) => !prev);

  const navLinks = useMemo(() => {
    return NAVIGATION_LINKS.map(({ name, href }) => ({
      name,
      href:
        isLoggedIn && name === "Home"
          ? userInfo.user.role === "admin"
            ? "/admin"
            : "/user"
          : href
    }));
  }, [isLoggedIn]);

  return (
    <header
      className=" header relative z-50 flex flex-wrap sm:justify-start sm:flex-nowrap w-full backdrop-blur-lg text-sm py-3 dark:from-gray-800 dark:via-gry-700 dark:to-gray-600"
      data-aos="fade-down"
    >
      <nav className="max-w-[85rem] w-full mx-auto px-4 sm:flex sm:items-center sm:justify-between relative">
        {/* Logo and Brand */}
        <div className="flex items-center justify-between">
          <a
            className="flex-none text-xl font-semibold text-white focus:outline-none focus:opacity-80"
            aria-label="Navigate to Home"
            onClick={() => navigate("/")}
          >
            <span className="inline-flex items-center gap-x-2 text-xl font-semibold">
              <img
                className="w-10 h-auto rounded-2xl"
                src="https://static.vecteezy.com/system/resources/thumbnails/010/071/582/small/food-truck-logo-restaurant-delivery-service-food-truck-logo-vector.jpg"
                alt="Logo"
              />
              Brand
            </span>
          </a>

          {/* Hamburger Menu Button */}
          <div className="sm:hidden">
            <button
              type="button"
              className="flex justify-center items-center rounded-lg border bg-white text-gray-800 shadow-sm dark:bg-transparent dark:border-gray-600 dark:text-white"
              aria-expanded={isMenuOpen}
              onClick={toggleMenu}
            >
              {isMenuOpen ? (
                <HiX className="block w-6 h-6" />
              ) : (
                <HiMenuAlt3 className="block w-6 h-6" />
              )}
            </button>
          </div>
        </div>

        {/* Navigation Links */}
        <div
          id="navbar-menu"
          className={`hs-collapse overflow-hidden transition-all duration-300 sm:block ${
            isMenuOpen ? "block" : "hidden"
          }`}
        >
          <div
            className="flex flex-col gap-5 mt-5 sm:flex-row sm:items-center sm:mt-0"
            data-aos="fade-up"
          >
            {navLinks.map(({ name, href }) => (
              <Link
                key={name}
                to={href}
                onClick={() => setIsMenuOpen(false)}
                className={`font-medium px-3 py-2 rounded-lg ${
                  location.pathname === href
                    ? "text-white border-b-2 border-red-600 bg-gray-700"
                    : "text-gray-200 hover:text-white dark:text-gray-400 dark:hover:text-white"
                }`}
              >
                {name}
              </Link>
            ))}

            {isLoggedIn ? (
              <div
                className="font-medium px-[3px] py-[2px] rounded-full bg-green-600 text-white hover:bg-green-700 dark:bg-gray-700 dark:hover:bg-gray-600 "
                onClick={openDialog}
              >
                <AccountCircleIcon />
              </div>
            ) : (
              <>
                <button
                  className="font-medium px-4 py-2 rounded-lg bg-green-600 text-white hover:bg-green-700 dark:bg-gray-700 dark:hover:bg-gray-600"
                  onClick={() => {
                    navigate("/sign-up");
                    setIsMenuOpen(false);
                  }}
                  data-aos="zoom-in"
                >
                  Sign Up
                </button>
                <button
                  className="font-medium px-4 py-2 rounded-lg bg-green-600 text-white hover:bg-green-700 dark:bg-gray-700 dark:hover:bg-gray-600"
                  onClick={() => {
                    navigate("/sign-in"), setIsMenuOpen(false);
                  }}
                  data-aos="zoom-in"
                >
                  Sign In
                </button>
              </>
            )}
          </div>
        </div>
      </nav>{" "}
      {/* Parent container */}
      {isLoggedIn && (
        <div className="">
          <Profile
            open={isOpen}
            close={closeDialog}
            update={""}
            logout={logout}
          />
        </div>
      )}
    </header>
  );
};

export default Header;
