import { useState } from "react";
import axios from "axios";
// import { useNavigate } from "react-router-dom";

// const navigate = useNavigate();
const Registeration = () => {
  const [formData, setFormData] = useState({
    name: "",
    username: "",
    password: "",
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prevState) => ({
      ...prevState,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // console.log(formData);
    setFormData({
      name: "",
      username: "",
      password: "",
    });

    const { name, username, password } = formData;
    // console.log(name, username, password);
    try {
      axios
        .post(
          "http://localhost:3535/register",
          { name, username, password },
          {
            headers: { "Content-Type": "application/json" },
          }
        )
        .then((result) => {
          if (result.data == "User Created Sucessfully") {
            console.log("User Created Sucessfully");
            // navigate("/login");
          } else {
            if (
              result.data == `User already exist using username ${username}, try other usernames`
            ) {
              console.log("Username Already exist try using different username");
            } else console.log("Server is Down!!");
          }
        });
    } catch (err) {
      console.log(err);
    }
  };

  return (
    <>
      {/* name: { type: String, required: true },
      username: { type: String, required: true, unique: true },
      password: { type: String, required: true }, */}
      <div>
        <div>
          <h2>Registration Page</h2>
          <form onSubmit={handleSubmit}>
            <div>
              <div>
                <label htmlFor="name">
                  <strong>Name:</strong>
                </label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  required
                />
              </div>
              <div>
                <label htmlFor="username">
                  <strong>Username:</strong>
                </label>
                <input
                  type="text"
                  name="username"
                  autoComplete="username"
                  value={formData.username}
                  onChange={handleChange}
                  required
                />
              </div>
              <div>
                <label htmlFor="password">
                  <strong>Password:</strong>
                </label>
                <input
                  type="password"
                  name="password"
                  autoComplete="new-password"
                  value={formData.password}
                  onChange={handleChange}
                  required
                />
              </div>
              <button type="submit">
                <strong>Register</strong>
              </button>
            </div>
          </form>
          <hr />
          <div>
            <p>Already have a account</p>
            <button>
              <strong>Login</strong>
            </button>
          </div>
        </div>
      </div>
    </>
  );
};

export default Registeration;
