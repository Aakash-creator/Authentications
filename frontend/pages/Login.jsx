import { useState } from "react";
import axios from "axios";

const Login = () => {
  const [formData, setFormData] = useState({
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
      username: "",
      password: "",
    });

    const { username, password } = formData;
    // console.log(username, password);
    try {
      axios
        .post(
          "http://localhost:3535/login",
          { username, password },
          {
            headers: { "Content-Type": "application/json" },
          }
        )
        .then((result) => {
          if (result.data == "User does not exist, register user before trying") {
            console.log("User does not exist, register user before trying");
          } else {
            if (result.data == "Incorrect Credentials") {
              console.log("Incorrect Credentials");
            } else {
              if (result.data == "Login Sucessfull!") {
                console.log("Login Sucessfull!"); // navigate("/dashboard");
              }
            }
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
          <h2>Login Page</h2>
          <form onSubmit={handleSubmit}>
            <div>
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
                <strong>Login </strong>
              </button>
            </div>
          </form>
          <hr />
          <div>
            <p>Create a new account</p>
            <button>
              <strong>Create Account</strong>
            </button>
          </div>
        </div>
      </div>
    </>
  );
};

export default Login;
