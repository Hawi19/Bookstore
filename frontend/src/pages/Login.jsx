import React from "react";
import { useState } from "react";
import axios from "axios";
import { useNavigate, Link } from "react-router-dom";
import { useSnackbar } from "notistack";
import { apiUrl } from "../api/server";

const Login = () => {
  const [username, setUsername] = useState("");

  const [password, setPassword] = useState("");
  const navigate = useNavigate();
  const { enqueueSnackbar } = useSnackbar();
  const handleLogin = () => {
    axios
      .post(`${apiUrl}/user/login`, { username, password })
      .then((response) => {
        const {token, username } = response.data;
        console.log("Username:", username);
        localStorage.setItem("token", token);
        localStorage.setItem("user", username);

        enqueueSnackbar("Login successful", { variant: "success" });
        navigate("/home", { state: { username } });
      })
      .catch((error) => {
        enqueueSnackbar(" Login Failed", { variant: "error" });
        console.log(error);
      });
  };
  return (
    <div className="p-4">
      <h1 className="mx-4 my-4">Log in</h1>
      <div className="p-4">
        <div className="my-4">
          <label className="mx-3 mr-4">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="px-4 py-2"
          />
        </div>

        <div className="my-4">
          <label className="mx-3 mr-4">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="px-4 py-2"
          />
        </div>
        <button
          className="btn btn-primary mx-4 my-2 p-2"
          style={{ width: 300 }}
          onClick={handleLogin}
        >
          Login
        </button>
        <div>
          <p className="mx-4">
            Already have an account? <Link to="/signup">SignUp</Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
