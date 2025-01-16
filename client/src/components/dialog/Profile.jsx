import React from "react";
import PropTypes from "prop-types";

import CloseIcon from "@mui/icons-material/Close";
import Button from "../buttons/Button";
import RestoreFromTrashIcon from "@mui/icons-material/RestoreFromTrash";
import CreateIcon from "@mui/icons-material/Create";
import useUserData from "../../hooks/update/useUserData";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";

function Profile({ open, close, update, deleted, logout }) {
  if (!open) return null; // Early return for better readability

  const { userInfo, isLoggedIn } = useSelector((state) => state.user);
  const navigate = useNavigate();

  // Default value for userData in case it is undefined
  const { userData, deleteUser } = useUserData(userInfo?.user?.id || null);

  // Check if userData exists before rendering its properties
  const name = userData?.name || "Default Name";
  const email = userData?.email || "default@example.com";
  const phone = userData?.phone || "000-000-0000";

  return (
    <div className="z-60 fixed right-1 top-14 sm:right-8 md:right-16 lg:right-2 xl:right-2 min-h-56">
      <div className="user-profile-container">
        <div className="users-profile grid grid-cols-1 gap-4 p-4  ">
          <div className="user-profile bg-white shadow-md rounded-lg p-4 relative min-w-60  max-w-xs sm:max-w-sm md:max-w-md lg:max-w-lg">
            {/* Profile Name */}
            <div className="user-profile-name flex items-center justify-center rounded-full h-16 w-16 mx-auto mb-4 bg-green-600">
              <div className="user-first-letter text-white text-xl font-bold">
                {name[0]}
              </div>
            </div>

            {/* Profile Details */}
            <ul className="user-profile-details text-center space-y-1">
              <li className="font-medium text-lg">{name}</li>
              <li className="text-sm text-gray-600">{email}</li>
              <li className="text-sm text-gray-600">{phone}</li>
            </ul>

            {/* Action Buttons */}
            <div className="btns flex justify-between mt-4">
              <Button
                className="text-green-800 border border-green-800 p-2 rounded hover:bg-green-800 hover:text-white transition duration-200"
                onClick={() => navigate(`/user/update/${userData?._id}`)}
                icon={<CreateIcon className="inline-block mr-1" />}
              />
              <Button
                className="text-rose-500 border border-rose-500 p-2 rounded hover:bg-rose-500 hover:text-white transition duration-200"
                onClick={() => deleteUser(_id)}
                icon={<RestoreFromTrashIcon className="inline-block mr-1" />}
              />
            </div>

            {/* Close Button */}
            <Button
              className="absolute top-2 right-2 text-gray-700 p-2 rounded-md hover:bg-gray-400 transition"
              onClick={close}
              icon={<CloseIcon className="inline-block" />}
            />

            {/* Logout Button */}
            <div className="logout mt-6 text-center">
              <button
                className="font-medium px-4 py-2 rounded-lg text-white hover:bg-green-700 dark:bg-gray-700 dark:hover:bg-gray-600 transition"
                onClick={logout}
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

Profile.propTypes = {
  id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
  open: PropTypes.bool,
  close: PropTypes.func.isRequired,
  update: PropTypes.func,
  deleted: PropTypes.func,
  logout: PropTypes.func.isRequired
};

Profile.defaultProps = {
  open: false,
  update: () => {},
  deleted: () => {}
};

export default Profile;
