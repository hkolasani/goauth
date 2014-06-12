/*
	This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    Created By: Hari Kolasani. June 8, 2014.

*/

/* This program contains the HTTP Server and the Request Handler 
    that calls the appropriate CRUD methods on the DBManager 
*/

//TODO: externalize error messages and codes

package main 

import (
	"io"
	"time"
	"net/http" 
	"net/url"
	"encoding/json"
	"fmt"
	"mongodb"
	"strings"
	"strconv"
	"errors"
	"labix.org/v2/mgo/bson"
	"io/ioutil"
	"crypto/rand"
	"scrypt"
)

const (
	
	MONGODB_URL = "mongodb://amsAppUser:password@localhost,localhost/AMS"
	SERVICES_URI = "/gomongo/services/"
	SIGNUP_URI = "/gomongo/signup"
	TOKENPURI = "/gomongo/auth/token"

	GET    = "GET"
	POST   = "POST"
	PUT    = "PUT"
	DELETE = "DELETE"
	MAX_ROWS = 2000
	
	PW_SALT_BYTES = 32
    PW_HASH_BYTES = 64

	USER_COLLECTION   		   = "orgusers"
	APPS_COLLECTION   		   = "apps"
	ACCESS_TOKEN_COLLECTION    = "accessTokens"
	REFRESH_TOKEN_COLLECTION   = "refreshTokens"
	
	ID         = "_id"
	GRANT_TYPE = "grant_type"
	USER_ID = "userid"
	USER_NAME = "username"
	PASSWORD = "password"
	PASSWORD_SALT = "passwordSalt"
	PASSWORD_HASH = "passwordHash"
	TOKEN = "token"
	CLIENT_ID = "client_id"
	CLIENT_SECRET = "client_secret"
	ACCESS_TOKEN = "access_token"
	REFRESH_TOKEN = "refresh_token"
	CREATED = "created"
	AUTHORIZATION_HEADER = "Authorization"
	
	TOKEN_EXPIRE_TIME = 900  //seconds
)

type User struct {
	userId string
	userName string
	hashedPassword string
	salt string
	fullName string
	email string
	phone string
	created time.Time
	createdBy string
}

type App struct {
	clientId string
	clientSecret string
	callbackURL string
}

type Token struct {
	userId string
	clientId string
	token string
	created time.Time
}

var dbMgr *mongodb.DBManager

func main() {

	 err := initDB()
	 
	 if err == nil {
		 mux := http.NewServeMux()
	
	 	mux.HandleFunc(SERVICES_URI, handleServiceRequest)
	 	mux.HandleFunc(SIGNUP_URI, handleSignUpRequest)
	 	mux.HandleFunc(TOKENPURI, handleTokenRequest)
	 
	 	fmt.Println("Listening ...")
	 	
     	http.ListenAndServe(":8088", mux)
     	
     } else {
     	fmt.Println("Failed to Start the Server:",err.Error())
     }
}

func initDB() (err error) {

	dbMgr  = mongodb.NewDBManager()
	
	err = dbMgr.InitSession(MONGODB_URL)  //TODO: Externalize the URL
	
	if err != nil {
          err = errors.New("Unable to Conenct to the Database :" + err.Error())
    }
    
    return err
}

/************************************* oAuth Request Handlers ******************************/

func handleSignUpRequest(response http.ResponseWriter, request *http.Request) {
	
	switch request.Method {

		case GET:
		 	handleUnsupported(response)  
		case POST:
			processSignupRequest(response,request)
		case PUT:
			handleUnsupported(response)
		case DELETE:
			handleUnsupported(response)
	}
}

func handleTokenRequest(response http.ResponseWriter, request *http.Request) {
	
	switch request.Method {

		case GET:
		    handleUnsupported(response)	  
		case POST:
			processTokenRequest(response,request)
		case PUT:
			handleUnsupported(response)
		case DELETE:
			handleUnsupported(response)
	}
}

/************************************* Service Request Handlers ******************************/

func handleServiceRequest(response http.ResponseWriter, request *http.Request) {
	
	//Check Access Token in Header to see if it is valid and has not expired)
    var token string
    
    authHeader :=request.Header.Get(AUTHORIZATION_HEADER)
    
    headerSplits := strings.Split(authHeader," ")
    if len(headerSplits) == 1 {
    	token = headerSplits[0]
    }else if len(headerSplits) == 2 {
    	token = headerSplits[1]
    }else {
    
    }
    
    err := validateAccessToken(token) 
    
    if err != nil {
    	mwError := bson.M{"errorCode":"500","errorMessage":"Invalid or Expired Token"}
		content,_ := json.MarshalIndent(mwError, "", "  ")
		response.Header().Add("Content-Type","application/json") 
	   	response.Write(content)
	   	
	   	return
    }
      
	switch request.Method {

		case GET:
		 	processGET(response,request)  
		case POST:
			processPOST(response,request)
		case PUT:
			processPUT(response,request)
		case DELETE:
			processDELETE(response,request)
	}
}

func handleUnsupported(response http.ResponseWriter) {

	mwError := bson.M{"errorCode":"500","errorMessage":"Unsupported Request Type"}
	content,_ := json.MarshalIndent(mwError, "", "  ")
	
	response.Header().Add("Content-Type","application/json") 

   	response.Write(content)
}

/************************************* oAuth Request Processors ******************************/

func validateAccessToken(tokenString string) (err error) {
	
	var token mongodb.Document
	
	token,err = getToken(tokenString,"",ACCESS_TOKEN_COLLECTION) 
	
	if err == nil {
		//check if it's expired
		diff := time.Now().Sub(token[CREATED].(time.Time))
		if diff.Seconds() > TOKEN_EXPIRE_TIME {
			err = errors.New("Token Expired!") 
			return err
		}
		//check if user exists 
		_,err = getUser(mongodb.Document{ID:token[USER_ID]}) //get user from db
	}
	
	return err
}

func processSignupRequest(response http.ResponseWriter, request *http.Request) {

	var err error
	var user mongodb.Document
	var content []byte
	var docId bson.ObjectId
	var salt []byte
	var hash []byte
	var result []mongodb.Document
	
	defer request.Body.Close()	
		
	//get POSTed data and unmarshall to JSON	
   	body, _ := ioutil.ReadAll(request.Body)
   	err = json.Unmarshal(body, &user)
    
    //check JSON validity of posteed data 
    if err == nil {
    	//check if username already exists
    	query := mongodb.Document{USER_NAME: user[USER_NAME]}
    	result,err = dbMgr.RunQuery(USER_COLLECTION,query,nil,nil,1)
    	if err == nil && (result == nil || len(result) == 0) { //crete new user
    		//generate salt and hashed password
	 		salt,err = generateSalt() 
	 		if err == nil {
	 			hash,err = generateHash((user["password"]).(string),salt)
	 			if err == nil { 
	 				user[PASSWORD_SALT] = salt
 	    			user[PASSWORD] = hash
					err,docId = dbMgr.InsertDocument(USER_COLLECTION,user)	
	 			}
	 		}
	 	}else { 
	 		if(err != nil) { //error tryign to find if the user alredy exists
	 			err = errors.New("Unable to verify existence of the User: " + err.Error())
	 		} else { //user exists
	 			err = errors.New("User already exists in the system")
	 		}
	 	}
	}else {
		err = errors.New("Invalid JSON Data: " + err.Error())
	}
    
	//check for result of the Insert
	if err != nil {
		mwError := bson.M{"errorCode":"500","errorMessage":errors.New("SignUp Failed - " + err.Error()).Error()}
		content,err = json.MarshalIndent(mwError, "", "  ")
	}else {
		successData := bson.M{"success":true,"message":"Signed Up Successfully!","_id":docId}
		content,_ = json.MarshalIndent(successData, "", "  ")
	}
	
	response.Header().Add("Content-Type","application/json") 

   	response.Write(content)   
}

func processTokenRequest(response http.ResponseWriter, request *http.Request) {

	var err error
	var grantType string
	var authRequest mongodb.Document
	var content []byte
	
	defer request.Body.Close()	
		
	//get POSTed data and unmarshall to JSON	
   	body, _ := ioutil.ReadAll(request.Body)
   	err = json.Unmarshal(body, &authRequest)
    
    //check JSON validity of posteed data 
    if err == nil {
		err = checkAuthRequest(authRequest)
		if(err == nil) {
			grantType = authRequest[GRANT_TYPE].(string)
			if(grantType == PASSWORD) {
				content =  processPasswordFlow(authRequest)   //password flow
			} else { // grantType == REFRESH_TOKEN
				content =  processRefreshTokenFlow(authRequest)  //refresh token flow
			}
		} else {  //invalid auth request parms
			err = errors.New("Invalid Auth Request: " + err.Error())
			mwError := bson.M{"errorCode":"500","errorMessage":err.Error()}
			content,_ = json.MarshalIndent(mwError, "", "  ")
		}
	}else {
		err = errors.New("Invalid JSON Data: " + err.Error())
		mwError := bson.M{"errorCode":"500","errorMessage":err.Error()}
		content,_ = json.MarshalIndent(mwError, "", "  ")
	}
	
	response.Header().Add("Content-Type","application/json") 

   	response.Write(content)   
}

func processPasswordFlow(authRequest mongodb.Document) (responseContent []byte) {

	var err error
	var user mongodb.Document
	var hash []byte
	var accessToken mongodb.Document
	var refreshToken mongodb.Document
	
	user,err = getUser(mongodb.Document{USER_NAME:authRequest[USER_NAME].(string) }) //get user from db
	
	if err == nil {
		//check password
		hash,err = generateHash((authRequest[PASSWORD]).(string),user[PASSWORD_SALT].([]byte))
		if err == nil {
			if string(hash) == string(user[PASSWORD].([]byte)) { //password hashes matched
				//create tokens
				accessToken,err = generateToken(user,authRequest,ACCESS_TOKEN_COLLECTION) 
				if err == nil {
					refreshToken,err = generateToken(user,authRequest,REFRESH_TOKEN_COLLECTION)
				}
			}else {
				err = errors.New("Invalid Password")
			}
		} else {
			err = errors.New("Unable to verify Password!. Hashing Error: " + err.Error())
		}
	}

	if err != nil { 
		mwError := bson.M{"errorCode":"500","errorMessage":err.Error()}
		responseContent,_ = json.MarshalIndent(mwError, "", "  ")
	}else {
		//success reponse with toekn info.
		tokenInfo := bson.M{ACCESS_TOKEN:accessToken[TOKEN],REFRESH_TOKEN:refreshToken[TOKEN]}
		responseContent,_ = json.MarshalIndent(tokenInfo, "", "  ")
	}
	
	return responseContent
}

func processRefreshTokenFlow(authRequest mongodb.Document) (responseContent []byte) {
	
	var err error
	var user mongodb.Document
	var token mongodb.Document
	var accessToken mongodb.Document
	var refreshToken mongodb.Document
	
	token,err = getToken(authRequest[REFRESH_TOKEN].(string),authRequest[CLIENT_ID].(string),REFRESH_TOKEN_COLLECTION) 
	
	if err == nil {
		//check if user exists 
		user,err = getUser(mongodb.Document{ID:token[USER_ID]}) //get user from db
		if err == nil {
			//create tokens
			accessToken,err = generateToken(user,authRequest,ACCESS_TOKEN_COLLECTION) 
			if err == nil {
				refreshToken,err = generateToken(user,authRequest,REFRESH_TOKEN_COLLECTION)
			}
		}
	}

	if err != nil { 
		mwError := bson.M{"errorCode":"500","errorMessage":err.Error()}
		responseContent,_ = json.MarshalIndent(mwError, "", "  ")
	}else {
		//success reponse with toekn info.
		tokenInfo := bson.M{ACCESS_TOKEN:accessToken[TOKEN],REFRESH_TOKEN:refreshToken[TOKEN]}
		responseContent,_ = json.MarshalIndent(tokenInfo, "", "  ")
	}
	
	return responseContent
}

/************************************* Service Request Processors ******************************/

func processGET(response http.ResponseWriter, request *http.Request) {

	var result []mongodb.Document
	var err error
	var content []byte
	var queryParms mongodb.Document
	var selectParms mongodb.Document
	var docId string
	
	serviceURL := request.URL
	
	collection := getCollectionName(serviceURL)
	
	docId = getDocId(serviceURL)
	
	if len(docId) != 0  { //get document by Id

		result,err = dbMgr.GetDocument(collection,docId)
		
	} else { //run the query using query aprms
	
		queryParms,err = getParms(serviceURL,"q")
		if err == nil { //query parms look good .. 
			selectParms,err = getParms(serviceURL,"select")
		}

		sortParms := getSortParms(serviceURL) //get any sort parms
	
		limit := getLimit(serviceURL)  //get any limit that's passed
	
		if err == nil {
			result,err = dbMgr.RunQuery(collection,queryParms,selectParms,sortParms,limit)
		}
	}

	//check for results
	if err != nil {
		mwError := bson.M{"errorCode":"500","errorMessage":err.Error()}
		content,err = json.MarshalIndent(mwError, "", "  ")
	}else {
		if result == nil || len(result) == 0 {
			content,err = json.MarshalIndent(map[string]mongodb.FieldValue{"errorCode":"404","errorMessage":"No Data Found"}, "", "  ")
		} else {
			content,err = json.MarshalIndent(result, "", "  ")	
		}
	}
	
	//something went wrong marshalling response
	if err != nil { 
		mwError := bson.M{"errorCode":"500","errorMessage":err.Error()}
		content,_ = json.MarshalIndent(mwError, "", "  ")
	}
	
	response.Header().Add("Content-Type","application/json") 

   	response.Write(content)   
}

func processPOST(response http.ResponseWriter, request *http.Request) {

	var err error
	var data mongodb.Document
	var content []byte
	var docId bson.ObjectId
	
	serviceURL := request.URL
	collection := getCollectionName(serviceURL)

	defer request.Body.Close()	
		
	//get POSTed data and unmarshall to JSON	
   	body, _ := ioutil.ReadAll(request.Body)
   	err = json.Unmarshal(body, &data)
    
    //check JSON validity of posteed data 
    if err != nil {
		err = errors.New("Invalid JSON Data: " + err.Error())
	}else {
		err,docId = dbMgr.InsertDocument(collection,data)	
	}
    
	//check for result of the Insert
	if err != nil {
		mwError := bson.M{"errorCode":"500","errorMessage":errors.New("POST Failed - " + err.Error()).Error()}
		content,err = json.MarshalIndent(mwError, "", "  ")
	}else {
		successData := bson.M{"success":true,"message":"Posted Successfully!","_id":docId}
		content,err = json.MarshalIndent(successData, "", "  ")
	}
	
	//something went wrong marshalling response
	if err != nil { 
		mwError := bson.M{"errorCode":"500","errorMessage":err.Error()}
		content,_ = json.MarshalIndent(mwError, "", "  ")
	}
	
	response.Header().Add("Content-Type","application/json") 

   	response.Write(content)   
}

func processPUT(response http.ResponseWriter, request *http.Request) {

	var err error
	var content []byte
	var docId string
	var data mongodb.Document
	
	serviceURL := request.URL
	
	collection := getCollectionName(serviceURL)
	
	docId = getDocId(serviceURL)
	
	if len(docId) != 0  { //delete document
		if bson.IsObjectIdHex(docId) {
			//get POSTed data and unmarshall to JSON	
   			body, _ := ioutil.ReadAll(request.Body)
   			err = json.Unmarshal(body, &data)
    		//check JSON validity of posteed data 
    		if err != nil {
				err = errors.New("Invalid JSON Data: " + err.Error())
			}else {
				query := mongodb.Document{"_id": bson.ObjectIdHex(docId)}
				err = dbMgr.UpdateDocument(collection,query,data)
			}
    	}else {
     		err = errors.New("Invalid Document Id")
    	}
	} else { 
		err = errors.New("Please provide the Id of the document to be Updated")
	}

	//check for result of the Update
	if err != nil {
		mwError := bson.M{"errorCode":"500","errorMessage":errors.New("UPDATE Failed - " + err.Error()).Error()}
		content,err = json.MarshalIndent(mwError, "", "  ")
	}else {
		successData := bson.M{"success":true,"message":"Updated Successfully!"}
		content,err = json.MarshalIndent(successData, "", "  ")
	}
	
	//something went wrong marshalling response
	if err != nil { 
		mwError := bson.M{"errorCode":"500","errorMessage":err.Error()}
		content,_ = json.MarshalIndent(mwError, "", "  ")
	}
	
	response.Header().Add("Content-Type","application/json") 

   	response.Write(content)   
}

func processDELETE(response http.ResponseWriter, request *http.Request) {

	var err error
	var content []byte
	var docId string
	
	serviceURL := request.URL
	
	collection := getCollectionName(serviceURL)
	
	docId = getDocId(serviceURL)
	
	if len(docId) != 0  { //delete document
		if bson.IsObjectIdHex(docId) {
			err = dbMgr.DeleteDocument(collection,mongodb.Document{"_id": bson.ObjectIdHex(docId)})
    	}else {
     		err = errors.New("Invalid Document Id")
    	}
	} else { 
		err = errors.New("Please provide the Id of the document to be Deleted")
	}

	//check for result of the Insert
	if err != nil {
		mwError := bson.M{"errorCode":"500","errorMessage":errors.New("DELETE Failed - " + err.Error()).Error()}
		content,err = json.MarshalIndent(mwError, "", "  ")
	}else {
		successData := bson.M{"success":true,"message":"Deleted Successfully!"}
		content,err = json.MarshalIndent(successData, "", "  ")
	}
	
	//something went wrong marshalling response
	if err != nil { 
		mwError := bson.M{"errorCode":"500","errorMessage":err.Error()}
		content,_ = json.MarshalIndent(mwError, "", "  ")
	}
	
	response.Header().Add("Content-Type","application/json") 

   	response.Write(content)   
}


//************************************* Utility Fucntions ****************************//

func getCollectionName(serviceURL *url.URL) (string) {

	path := serviceURL.Path    // 'gomongo/services/collectionName/documentId
	
	pathSplits := strings.Split(path,"/")

	return pathSplits[3]
}

func getDocId(serviceURL *url.URL) (string) {

	path := serviceURL.Path    // 'gomongo/services/collectionName/documentId
	
	pathSplits := strings.Split(path,"/")
	
	if len(pathSplits) > 4 {
		return pathSplits[4]
	}
	
	return ""
}

func getParms(serviceURL *url.URL,parmType string) (parmsDocument mongodb.Document,err error ) {

	var parmsString string 
	
	rawQuery := serviceURL.RawQuery
	
    parmsMap, _ := url.ParseQuery(rawQuery)

    if(parmsMap[parmType] != nil && len(parmsMap[parmType][0]) > 0) {
   		parmsString =  parmsMap[parmType][0]
   		err = json.Unmarshal([]byte(parmsString) , &parmsDocument)
   	}else {
   		return nil,nil
   	}
   	
   	if err != nil {
   		if parmType == "q" {
   			err = errors.New("Invalid Query Parms- " + err.Error())
   		} else {
   			err = errors.New("Invalid Select Parms-" + err.Error())
   		}
   	}
 
  	return parmsDocument,err
}

func getSortParms(serviceURL *url.URL) (sortParms []string) {
 
	rawQuery := serviceURL.RawQuery
	
    parmsMap, _ := url.ParseQuery(rawQuery)

    if(parmsMap["sort"] != nil && len(parmsMap["sort"][0]) > 0) {
   		sortParms =  parmsMap["sort"]
   	}
 
  	return sortParms
}

func getLimit(serviceURL *url.URL) (limit int) {

	var err error
	limit = MAX_ROWS
	
	rawQuery := serviceURL.RawQuery
	
    parmsMap, _ := url.ParseQuery(rawQuery)

    if(parmsMap["limit"] != nil && len(parmsMap["limit"][0]) > 0) {
    	limitString := parmsMap["limit"][0]
   		limit,err = strconv.Atoi(limitString) 
   		if err != nil {
   			limit = MAX_ROWS
   		}
   	}
 
  	return limit
}

func checkAuthRequest(authRequest mongodb.Document) (err error) {
	
	grantType := authRequest[GRANT_TYPE]
	clientId := authRequest[CLIENT_ID]
	clientSecret := authRequest[CLIENT_SECRET]
	
	if(grantType == nil || clientId == nil || clientSecret == nil)  {
		err = errors.New("grant_type,client_id and client_secret are required")
		return 
	}
	
	grantTypeStr := authRequest[GRANT_TYPE].(string)
	
	if grantTypeStr == PASSWORD {
		userName := authRequest[USER_NAME]
		password := authRequest[PASSWORD]
		if userName == nil || password == nil  {
			err = errors.New("user_name and password are required")
			return 
		}
	}else if grantTypeStr == REFRESH_TOKEN {
		refreshToken := authRequest[REFRESH_TOKEN]
		if refreshToken == nil {
			err = errors.New("refresh_token is required")
			return 
		}
	}else {
		err = errors.New("Invalid grant_type: " +  grantTypeStr)
	}
	
	return err
}

func generateToken(user mongodb.Document,authRequest mongodb.Document,tokenCollection string) (token mongodb.Document,err error) {

	token = mongodb.Document{USER_ID:user[ID],CLIENT_ID:authRequest[CLIENT_ID],TOKEN:randString(64),CREATED:time.Now()}
	
	//delete the token if exists
	err = dbMgr.DeleteDocument(tokenCollection,mongodb.Document{USER_ID:user[ID],CLIENT_ID:authRequest[CLIENT_ID]})
    
    if err == nil || err.Error() == "not found" {
    	//insert token
    	err,_ = dbMgr.InsertDocument(tokenCollection,token)      
    } 
		
	if(err != nil) {
		err = errors.New("Failed to Generate Token " + err.Error())
	}
	
	return token,err
}

func getUser(query mongodb.Document) (user mongodb.Document,err error)  {

	var result []mongodb.Document

    result,err = dbMgr.RunQuery(USER_COLLECTION,query,nil,nil,1)
    if err != nil { 
		err = errors.New("Unable to retrieve User:" + err.Error())
	} else if result == nil || len(result) == 0 { 
		err = errors.New("User Not found!")
	}else if len(result) > 1 { 
		err = errors.New("Ambiguous username!. Multiple users exists with the same username")
	}else {
		user = result[0]
	}
	
	return user,err
}

func getToken(tokenString string,clientId string,tokenCollection string) (token mongodb.Document,err error)  {

	var result []mongodb.Document
	var query mongodb.Document
	
	if len(clientId) == 0 {
		query = mongodb.Document{TOKEN: tokenString}
	}else {
		query = mongodb.Document{TOKEN: tokenString,CLIENT_ID:clientId}
	}
	
    result,err = dbMgr.RunQuery(tokenCollection,query,nil,nil,1)
    
    if err != nil { 
		err = errors.New("Unable to retrieve Token:" + err.Error())
	} else if result == nil || len(result) == 0 { 
		err = errors.New("Token Not Found!")
	}else if len(result) > 1 { 
		err = errors.New("Ambiguous Token!. Multiple Instances")
	}else {
		token = result[0]
		
		if err!= nil && token == nil {
			err = errors.New("Token Not Found!")
		}
	}
	
	return token,err
}

func generateSalt() (salt []byte,err error) {

    salt = make([]byte, PW_SALT_BYTES)

    _, err = io.ReadFull(rand.Reader, salt)
    
    return salt,err
}

func generateHash(password string,salt []byte) (hash []byte,err error) {

    hash, err = scrypt.Key([]byte(password), salt, 1<<14, 8, 1, PW_HASH_BYTES)
    
    if err != nil {
        return hash,err
    }

    return hash,err
}

func randString(n int) string {
    const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    var bytes = make([]byte, n)
    rand.Read(bytes)
    for i, b := range bytes {
        bytes[i] = alphanum[b % byte(len(alphanum))]
    }
    return string(bytes)
}
