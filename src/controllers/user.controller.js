import {asyncHandler} from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
const generateAccessAndRefreshToken = async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refereshToken = user.generateRefreshToken()

        user.refereshToken = refereshToken
        await user.save({ValidateBeforeSave:false})
        return {accessToken, refereshToken}

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating token")
    }
}

// Register User function
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
      //const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length>0){
        coverImage = req.files.coverImage[0].path;
    }
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

// Login User Function

const loginUser = asyncHandler(async(req, res)=>{
    // fetch data
    const {username, email, password} = req.body;
   // validation username or email
   if(!username && !email){
    throw new ApiError(404, "username or email is required")
   }
   // find the user and validation
   const user = await User.findOne({
    $or:[{username}, {email}]
   })
   if(!user){
    throw new ApiError(404, "User does not exist")
   }
   // password check and validation
   const isPasswordValid = await user.isPasswordCorrect(password)
   if(!isPasswordValid){
    throw new ApiError(401, "Invalid user credentials")
   }

   //access and referesh token genrate
   const {accessToken, refereshToken} = await generateAccessAndRefreshToken(user._id)
   const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

   // send cookie 
   const options = {
    httpOnly: true,
    secure:true
   }
   return res
   .status(200)
   .cookie("accessToken", accessToken, options)
   .cookie("refereshToken", refereshToken, options)
   .json(new ApiResponse(200, {
    user: loggedInUser, accessToken, refereshToken
   }, "User logged In Successfully"
   ))

})

// logged Out
const logoutUser = asyncHandler(async(req, res)=> {
    await User.findByIdAndUpdate(req.user._id, {
        $set:{refreshToken: undefined}
    },{new:true})

    const options = {
        httpOnly: true,
        secure:true
    }
    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User Logged Out"))
})

// access the refresh token
const refreshAccessToken = asyncHandler(async(req, res) => {
    const incomingRefreshToken = req.cookies.refereshToken || req.body.refereshToken
    if(incomingRefreshToken){
        throw new ApiError(401, "Unauthorized request")
    }
    try {
        const decodeToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
        const user = await User.findById(decodeToken?._id)
        if(user){
            throw new ApiError(401, "Invalid refresh token")
        }
        if(!incomingRefreshToken !== user?.refereshToken){
            throw new ApiError(401, "Refresh token is expired or used")
        }
        const options ={
            httpOnly: true,
            secure:true
        }
        const{accessToken, newrefereshToken} = await generateAccessAndRefreshToken(user._id)
        return res.status(200).cookie("accessToken", accessToken, options).cookie("refreshToken", newrefereshToken, options)
        .json(
            new ApiResponse(200, {accessToken, refreshToken:newrefereshToken}, "Access token refreshed")
        )
    } catch (error) {
       throw new ApiError(401, err?.message || "Invalid refresh token") 
    }
})

// change password
const changeCurrentPassword = asyncHandler(async(req, res) => {
    const {oldPassword, newPassword} = req.body;
    if(!oldPassword && !newPassword){
        throw new ApiError(400, "All fields are required")
    }
    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
    if(!isPasswordCorrect){
        throw new ApiError(400, "Invalid Old Password")
    }
    user.password = newPassword
    await user.save({ValidateBeforeSave:false})
    return res.status(200).json(new ApiResponse(200, {}, "Password change Successfully"))
})

// get the current user
const getCurrentUser = asyncHandler(async(req, res)=>{
    return res.status(200).json(200, req.user, "Current user fetched successfully")
})

// update account details
const updateAccountDetails = asyncHandler(async(req, res)=>{
    const{fullName, email} = req.body
    if(!fullName || !email){
        throw new ApiError(400, "All fields are required")
    }
    const user = await User.findByIdAndUpdate(req.user?._id, {
        $set:{
            fullName, email
        }
    }, {new:true}).select("-password")

    return res.status(200).json(new ApiResponse(200, user, "Account details updated successfully"))
})

// update file
const updateUserAvatar = asyncHandler(async(req, res)=>{
    const avatarLocalPath = req.file?.path
    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is missing")
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    if(!avatar.url){
        throw new ApiError(400, "Error while uploading on avatar")
    }

    const user = await User.findByIdAndUpdate(req.user?._id, {
        $set:{
            avatar: avatar.url
        }
    },{new:true}).select("-password")
    return res.status(200).json(new ApiResponse(200,user, "Avatar updated successfully"))
})
const updateUserCoverImage = asyncHandler(async(req, res)=>{
    const coverImageLocalPath = req.file?.path
    if(!coverImageLocalPath){
        throw new ApiError(400, "CoverImage file is missing")
    }
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if(!coverImage.url){
        throw new ApiError(400, "Error while uploading on avatar")
    }

    const user = await User.findByIdAndUpdate(req.user?._id, {
        $set:{
            coverImage: coverImage.url
        }
    },{new:true}).select("-password")
    return res.status(200).json(new ApiResponse(200,user, "CoverImage updated successfully"))
})

// Writing Aggregation Pipelines
const getUserChannelProfile = asyncHandler(async(req, res)=>{
    const {username} = req.params
    if(!username?.trim){
        throw new ApiError(400, "Username is missing")
    }
    const channel = await User.aggregate([
        {
            $match:{
                username: username?.toLowerCase()
            }
        },{
            $lookup:{
                from:"subscriptions",
                localField: "_id",
                foreignField: "channel",
                as:"subscribers"
            }
        },
        {
            $lookup:{
                from:"subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as:"subscribedTo"
            }
        },
        {
            $addFields:{
                subscribersCount:{
                    $size: "$subscribers"
                },
                channelsSubscribedToCount:{
                    $size: "$subscribedTo"
                },
                isSubscribed:{
                    $cond:{
                        if:{$in:[req.user?._id, "$subscribers.subscriber"]},
                        then:true,
                        else:false
                    }
                }
            }
        },
        {
            $project: {
                fullName: 1,
                username: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1,
            }
        }
    ])
    if(!channel?.length){
        throw new ApiError(404, "channel does not exists")
    }
    return res.status(200).json(
        new ApiResponse(200, channel[0], "User channel fetchwd successfully")
    )

})



export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile
}
