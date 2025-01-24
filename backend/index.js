import express, { request, response } from "express";
import { PORT, mongoDBURL } from "./config.js";
import mongoose from "mongoose";
import userRoute from './routes/userRoute.js'
import booksRoute from "./routes/booksRoute.js";
import cors from "cors";


const app = express();
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static("uploads"));
//Middleware for parsing request body
app.use(express.json());
//Middleware for handling CORS POLICY
//Allow All Origins qith difault of cors(*)
app.use(cors());
let corsOptions = {
  origin: [
    "https://bookstore-frontend-ddb5.onrender.com/",
    "http://localhost:5173",
  ],
};
app.use(cors(corsOptions));
app.get("/", (request, response) => {
  console.log(request);
  return response.status(234).send("Welcome To MERN Stack Tutorial");
});
app.use("/books", booksRoute);
app.use("/user", userRoute);


mongoose
  .connect(mongoDBURL)
  .then(() => {
    console.log("App connected to database");
    app.listen(PORT, () => {
      console.log(`App is listening to port: ${PORT}`);
    });
  })
  .catch((error) => {
    console.log(error);
  });
