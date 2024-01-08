// userController.js
const User = require("../models/user");



// exports.getUser = async (req, res) => {
//   try {
//     const { _id: id } = req.user;
//     const user = await User.findById(id);

//     if (!user) {
//       return res.status(404).json({ message: "User not found." });
//     }

//     res.status(200).json({ ...user._doc, password: undefined });
//   } catch (error) {
//     console.error("Get User Error:", error);
//     res.status(500).json({ error: "Unexpected error while fetching user." });
//   }
// };

exports.updateUser = async (req, res) => {
  try {
    const { _id: id } = req.user;
    const { firstName, lastName } = req.body;

    await User.findByIdAndUpdate(id, { firstName, lastName });
    res.status(200).json({ message: "User updated successfully" });
  } catch (error) {
    console.error("Update User Error:", error);
    res.status(500).json({ error: "Unexpected error during user update." });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    const { _id: id } = req.user;

    await User.findByIdAndDelete(id);
    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Delete User Error:", error);
    res.status(500).json({ error: "Unexpected error during user deletion." });
  }
};
