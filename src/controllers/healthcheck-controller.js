import {ApiResponse} from "../utlis/api-response.js";
import { asyncHandler } from "../utlis/async-handler.js";


/** 

const healthCheck = async (req,res, next) =>{
  try {
    const user=await getuserFromDB()
    res.status(200).json(
      new ApiResponse(200,{message : "Server is Running"})
    );
    
  } catch (error) {
    next(err)
  }
};
 */

const healthCheck=asyncHandler(async(req,res)=>{
  res
  .status(200)
  .json(
    new ApiResponse(200,{message:"server is running"})
  );
});


export {healthCheck};
