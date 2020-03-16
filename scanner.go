package ldap

import (
	"github.com/shubinmi/util/errs"
)

type ResultsScanner interface {
	Next() bool
	LastErr() error
	Scan(setter func(res interface{}))
}

func GroupsSetter(gs *[]Group) func(res interface{}) {
	return func(res interface{}) {
		if res == nil {
			return
		}
		items := res.([]interface{})
		for _, item := range items {
			*gs = append(*gs, item.(Group))
		}
	}
}

func UnitsSetter(us *[]Unit) func(res interface{}) {
	return func(res interface{}) {
		if res == nil {
			return
		}
		items := res.([]interface{})
		for _, item := range items {
			*us = append(*us, item.(Unit))
		}
	}
}

func UsersSetter(us *[]User) func(res interface{}) {
	return func(res interface{}) {
		if res == nil {
			return
		}
		items := res.([]interface{})
		for _, item := range items {
			*us = append(*us, item.(User))
		}
	}
}

type scanner struct {
	result    interface{}
	retriever func() (interface{}, error)
	lastErr   error
	done      bool
}

func newScanner(retriever func() (interface{}, error)) *scanner {
	return &scanner{retriever: retriever}
}

func (s scanner) LastErr() error {
	return s.lastErr
}

func (s *scanner) Next() bool {
	if s.done {
		return false
	}
	gs, err := s.retriever()
	s.result = gs
	if err != nil && !errs.IsNothingToDo(err) {
		s.lastErr = err
	}
	if err != nil && errs.IsNothingToDo(err) {
		s.done = true
	}
	return s.lastErr == nil && s.result != nil
}

func (s scanner) Scan(loader func(res interface{})) {
	loader(s.result)
}
