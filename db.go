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


/* This program contains the wrapper methods for mGo calls. */

package mongodb

import (
        "errors"
        //"encoding/json"
        "labix.org/v2/mgo"
        "labix.org/v2/mgo/bson"
)

type FieldValue interface{}
type Document map[string]FieldValue

type DBManager struct {

	dbURL string
	pooledSession *mgo.Session
}

func NewDBManager() *DBManager {
	return &DBManager{}
}

func (dbManager *DBManager) InitSession(url string) error {

	var err error
	
	dbManager.dbURL = url
	
	dbManager.pooledSession, err = mgo.Dial(dbManager.dbURL)
	
   	return err
}

func (dbManager *DBManager) Term()  {

	if dbManager.pooledSession != nil {
    	 dbManager.pooledSession.Close()
    }
}

func (dbManager *DBManager) RunQuery(collectionName string,	queryParms Document,selectParms Document,sortParms []string,limit int) (result []Document, err error)  {
	
	if dbManager.pooledSession == nil {
    	return nil, errors.New("No Database Connection!") 
    }
   
	dbSession := dbManager.pooledSession.Copy()
	defer dbSession.Close()
	
    collection := dbSession.DB("").C(collectionName)
    
    query := collection.Find(queryParms)
    
    //set select parms
    if selectParms != nil {
    	query = query.Select(selectParms)
    }
    
    //set sort parms
    if sortParms != nil {
    	for _, sortParm := range sortParms {
			query = query.Sort(sortParm)
		}
    }
    
    //set limit
    query.Limit(limit)
 
 	//run query   
    err = query.All(&result)
        
    return result,err
}

func (dbManager *DBManager) GetDocument(collectionName string,	docId string) (result []Document, err error)  {
	
	if bson.IsObjectIdHex(docId) {
		queryParms := Document{"_id": bson.ObjectIdHex(docId)}
		return dbManager.RunQuery(collectionName,queryParms,nil,nil,1)
    }else {
     	return nil,errors.New("Invalid Document Id")
    }
}

func (dbManager *DBManager) InsertDocument(collectionName string,document Document) (err error,docId bson.ObjectId)  {
	
	if dbManager.pooledSession == nil {
    	return errors.New("No Database Connection!"),docId 
    }
   
	dbSession := dbManager.pooledSession.Copy()
	defer dbSession.Close()
	
    collection := dbSession.DB("").C(collectionName)
    
    docId = bson.NewObjectId()
    
    document["_id"] = docId  //generate Id
    
    err = collection.Insert(document)
        
    return err,docId
}

func (dbManager *DBManager) UpdateDocument(collectionName string,query Document,properties Document) (err error)  {
	
	if dbManager.pooledSession == nil {
    	return errors.New("No Database Connection!") 
    }
   
	dbSession := dbManager.pooledSession.Copy()
	defer dbSession.Close()
	
    collection := dbSession.DB("").C(collectionName)
    
    err = collection.Update(query,properties)
        
    return err
}

func (dbManager *DBManager) DeleteDocument(collectionName string,document Document) (err error)  {
	
	if dbManager.pooledSession == nil {
    	return errors.New("No Database Connection!") 
    }
   
	dbSession := dbManager.pooledSession.Copy()
	defer dbSession.Close()
	
    collection := dbSession.DB("").C(collectionName)
    
    err = collection.Remove(document)
        
    return err
}

