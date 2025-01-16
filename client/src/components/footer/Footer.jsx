import React from "react";

function Footer() {
  return (
    <div>
      <div className="bg-gray-100 text-center shadow-inner p-6 bottom-0">
        {/* Footer Bottom */}
        <div className="border-t pt-4">
          <p className="text-sm text-gray-600">
            &copy; {new Date().getFullYear()} Your Company. All rights reserved.
          </p>
          <p className="text-sm text-gray-600 space-x-4">
            <a
              href="/privacy-policy"
              className="hover:underline hover:text-blue-600"
              aria-label="Privacy Policy"
            >
              Privacy Policy
            </a>
            <span>|</span>
            <a
              href="/terms-of-service"
              className="hover:underline hover:text-blue-600"
              aria-label="Terms of Service"
            >
              Terms of Service
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}

export default Footer;
