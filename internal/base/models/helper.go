package models

import (
	"context"

	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type Tabler interface {
}
type GormScope func(*gorm.DB) *gorm.DB

const (
	noRows = 0
)

func Create[T Tabler](ctx context.Context, db *gorm.DB, tableName string, record ...*T) (err error) {
	if len(tableName) != 0 {
		return db.Table(tableName).Create(&record).Error
	}
	return db.Model(new(T)).Create(&record).Error
}

func CreateV2[T Tabler](ctx context.Context, db *gorm.DB, record ...*T) (err error) {
	return db.Model(new(T)).Create(&record).Error
}

func Update[T Tabler](ctx context.Context, db *gorm.DB, scope GormScope, strict bool, updates map[string]interface{}) (err error) {
	// if db == nil {
	// 	db, err = GetDB(utils.IdentifyKeyFromContext(ctx))
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	tx := db.Model(new(T)).Debug().Scopes(scope).Updates(updates)
	rows := tx.RowsAffected
	err = tx.Error

	if err != nil {
		return err
	}
	if strict && rows == noRows {
		return errors.Wrapf(gorm.ErrRecordNotFound, "updates:%+v", updates)
	}

	return err
}

func Get[T Tabler](ctx context.Context, db *gorm.DB, scope GormScope, strict bool, record *T, tableName string) (err error) {
	if len(tableName) == 0 {
		err = db.Model(record).Scopes(scope).Take(&record).Error
	}
	if len(tableName) != 0 {
		err = db.Table(tableName).Scopes(scope).Take(&record).Error
	}
	if !strict && errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	return err
}

func ListModelScopes[T Tabler](ctx context.Context, db *gorm.DB, scope GormScope, records *[]*T) error {
	return db.Model(new(T)).Scopes(scope).Session(&gorm.Session{}).Find(&records).Limit(-1).Offset(-1).Error
}

func List[T Tabler](ctx context.Context, db *gorm.DB, scope GormScope, records *[]*T) (count int64, err error) {
	err = db.Model(new(T)).Scopes(scope).Session(&gorm.Session{}).Find(&records).Limit(-1).Offset(-1).Count(&count).Error
	return count, err
}

func ListV2[T Tabler](ctx context.Context, db *gorm.DB, scope GormScope, records *[]*T, tableName string) (count int64, err error) {
	err = db.Table(tableName).Scopes(scope).Session(&gorm.Session{}).Find(&records).Limit(-1).Offset(-1).Count(&count).Error
	return count, err
}
