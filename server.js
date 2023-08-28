// server.js
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');

const app = express();
const port = 3001;

app.use(bodyParser.json());
const cors = require("cors");

app.use(cors({
  origin: ['http://localhost:3000'],
  credentials: true
}));

// Connect to MongoDB
mongoose.connect("mongodb+srv://follwersweb:follwersweb@cluster0.zltam.mongodb.net/followersweb?retryWrites=true&w=majority",{
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(()=>console.log("Database has been connected"))
.catch((error)=>console.log(`Error in database ${error}`))

// Use the auth routes
app.use('/auth', authRoutes);

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
