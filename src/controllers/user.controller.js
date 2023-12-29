import {asyncHandler} from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/ApiResponse.js";
const registerUser = asyncHandler( async (req, res) => {
    // get user details from frontend
    const{fullName, email, username, password} = req.body;

    // validation - not empty
    if(
        [fullName, email, username, password].some((field)=> field?.trim() === "") // it iterate over the array if any value is null it given true
    ){
        throw new ApiError(400, "All fields are required");
    }
    // check if user alredy exists: userName, email
    const existedUser = await User.findOne({
        $or:[{ username }, { email }]
    });
    if(existedUser){
        throw new ApiError(400, "User with email or username already exists");
    }
    // check for images, check for avatar
    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;
    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is required");
    }
    // upload them to cloudinary, avatar check
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    if(!avatar) throw new ApiError(400, "Avatar file is required");
    // create user object - create entry in db
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })
     // check for user creation & remove password and refresh token field from response
     const createdUser = await User.findById(user._id).select(
        "-password -refreshToken" // here we write this fiels which we not want  by default it select all
     );
     if(!createdUser){
        throw new ApiError(500, "Something went wrong while registering the user")
     }
    
    // return res
    return res.status(201).json(
        new ApiResponse(200, createdUser, "User Registered Successfully")
    )

})


export {registerUser}
