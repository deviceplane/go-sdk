package client

import (
	"time"
)

type ConditionType string

type Filter []Condition

type Condition struct {
	Type   ConditionType          `json:"type"`
	Params map[string]interface{} `json:"params"`
}

type UserCreate struct {
	Company   string `json:"company"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Password  string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type User struct {
	ID                    string    `json:"id" yaml:"id"`
	CreatedAt             time.Time `json:"createdAt" yaml:"createdAt"`
	Email                 string    `json:"email" yaml:"email"`
	FirstName             string    `json:"firstName" yaml:"firstName"`
	LastName              string    `json:"lastName" yaml:"lastName"`
	Company               string    `json:"company" yaml:"company"`
	RegistrationCompleted bool      `json:"registrationCompleted" yaml:"registrationCompleted"`
	SuperAdmin            bool      `json:"superAdmin" yaml:"superAdmin"`
}

type RegistrationToken struct {
	Name             string `json:"name" yaml:"name"`
	Description      string `json:"description" yaml:"description"`
	MaxRegistrations int    `json:"maxRegistrations" yaml:"maxRegistrations"`
}

type PasswordRecoveryToken struct {
	ID        string    `json:"id" yaml:"id"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
	UserID    string    `json:"userId" yaml:"userId"`
}

type Session struct {
	ID        string    `json:"id" yaml:"id"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
	UserID    string    `json:"userId" yaml:"userId"`
}

type UserAccessKey struct {
	ID          string    `json:"id" yaml:"id"`
	CreatedAt   time.Time `json:"createdAt" yaml:"createdAt"`
	UserID      string    `json:"userId" yaml:"userId"`
	Description string    `json:"description" yaml:"description"`
}

type UserAccessKeyWithValue struct {
	UserAccessKey
	Value string `json:"value" yaml:"value"`
}

type Project struct {
	ID            string    `json:"id" yaml:"id"`
	CreatedAt     time.Time `json:"createdAt" yaml:"createdAt"`
	Name          string    `json:"name" yaml:"name"`
	DatadogAPIKey *string   `json:"datadogApiKey" yaml:"datadogApiKey"`
}

type ProjectDeviceCounts struct {
	AllCount int `json:"allCount" yaml:"allCount"`
}

type ProjectApplicationCounts struct {
	AllCount int `json:"allCount" yaml:"allCount"`
}

type RoleCreate struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
	Config      string `json:"config" yaml:"config"`
}

type Role struct {
	ID          string    `json:"id" yaml:"id"`
	CreatedAt   time.Time `json:"createdAt" yaml:"createdAt"`
	ProjectID   string    `json:"projectId" yaml:"projectId"`
	Name        string    `json:"name" yaml:"name"`
	Description string    `json:"description" yaml:"description"`
	Config      string    `json:"config" yaml:"config"`
}

type Membership struct {
	UserID    string    `json:"userId" yaml:"userId"`
	ProjectID string    `json:"projectId" yaml:"projectId"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
}

type MembershipRoleBinding struct {
	UserID    string    `json:"userId" yaml:"userId"`
	RoleID    string    `json:"roleId" yaml:"roleId"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
	ProjectID string    `json:"projectId" yaml:"projectId"`
}

type ServiceAccountCreate struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
}

type ServiceAccount struct {
	ID          string    `json:"id" yaml:"id"`
	CreatedAt   time.Time `json:"createdAt" yaml:"createdAt"`
	ProjectID   string    `json:"projectId" yaml:"projectId"`
	Name        string    `json:"name" yaml:"name"`
	Description string    `json:"description" yaml:"description"`
}

type ServiceAccountAccessKey struct {
	ID               string    `json:"id" yaml:"id"`
	CreatedAt        time.Time `json:"createdAt" yaml:"createdAt"`
	ProjectID        string    `json:"projectId" yaml:"projectId"`
	ServiceAccountID string    `json:"serviceAccountId" yaml:"serviceAccountId"`
	Description      string    `json:"description" yaml:"description"`
}

type ServiceAccountAccessKeyWithValue struct {
	ServiceAccountAccessKey
	Value string `json:"value" yaml:"value"`
}

type ServiceAccountRoleBinding struct {
	ServiceAccountID string    `json:"serviceAccountId" yaml:"serviceAccountId"`
	RoleID           string    `json:"roleId" yaml:"roleId"`
	CreatedAt        time.Time `json:"createdAt" yaml:"createdAt"`
	ProjectID        string    `json:"projectId" yaml:"projectId"`
}

type Device struct {
	ID                   string            `json:"id" yaml:"id"`
	CreatedAt            time.Time         `json:"createdAt" yaml:"createdAt"`
	ProjectID            string            `json:"projectId" yaml:"projectId"`
	Name                 string            `json:"name" yaml:"name"`
	RegistrationTokenID  *string           `json:"registrationTokenId" yaml:"registrationTokenId"`
	DesiredAgentVersion  string            `json:"desiredAgentVersion" yaml:"desiredAgentVersion"`
	Info                 DeviceInfo        `json:"info" yaml:"info"`
	LastSeenAt           time.Time         `json:"lastSeenAt" yaml:"lastSeenAt"`
	Status               DeviceStatus      `json:"status" yaml:"status"`
	Labels               map[string]string `json:"labels" yaml:"labels"`
	EnvironmentVariables map[string]string `json:"environmentVariables" yaml:"environmentVariables"`
}

type DeviceStatus string

const (
	DeviceStatusOnline  = DeviceStatus("online")
	DeviceStatusOffline = DeviceStatus("offline")
)

type DeviceRegistrationToken struct {
	ID               string            `json:"id" yaml:"id"`
	CreatedAt        time.Time         `json:"createdAt" yaml:"createdAt"`
	ProjectID        string            `json:"projectId" yaml:"projectId"`
	MaxRegistrations *int              `json:"maxRegistrations" yaml:"maxRegistrations"`
	Name             string            `json:"name" yaml:"name"`
	Description      string            `json:"description" yaml:"description"`
	Labels           map[string]string `json:"labels" yaml:"labels"`
}

type DevicesRegisteredWithTokenCount struct {
	AllCount int `json:"allCount" yaml:"allCount"`
}

type DeviceAccessKey struct {
	ID        string    `json:"id" yaml:"id"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
	ProjectID string    `json:"projectId" yaml:"projectId"`
	DeviceID  string    `json:"deviceId" yaml:"deviceId"`
}

type MembershipFull1 struct {
	Membership
	User    User        `json:"user" yaml:"user"`
	Project ProjectFull `json:"project" yaml:"project"`
}

type ProjectFull struct {
	Project
	DeviceCounts      ProjectDeviceCounts      `json:"deviceCounts" yaml:"deviceCounts"`
	ApplicationCounts ProjectApplicationCounts `json:"applicationCounts" yaml:"applicationCounts"`
}

type MembershipFull2 struct {
	Membership
	User  User   `json:"user" yaml:"user"`
	Roles []Role `json:"roles" yaml:"roles"`
}

type ServiceAccountFull struct {
	ServiceAccount
	Roles []Role `json:"roles" yaml:"roles"`
}

type DeviceRegistrationTokenFull struct {
	DeviceRegistrationToken
	DeviceCounts DevicesRegisteredWithTokenCount `json:"deviceCounts" yaml:"deviceCounts"`
}

type DeviceInfo struct {
	AgentVersion string    `json:"agentVersion" yaml:"agentVersion"`
	IPAddress    string    `json:"ipAddress" yaml:"ipAddress"`
	OSRelease    OSRelease `json:"osRelease" yaml:"osRelease"`
}

type OSRelease struct {
	PrettyName string `json:"prettyName" yaml:"prettyName"`
	Name       string `json:"name" yaml:"name"`
	VersionID  string `json:"versionId" yaml:"versionId"`
	Version    string `json:"version" yaml:"version"`
	ID         string `json:"id" yaml:"id"`
	IDLike     string `json:"idLike" yaml:"idLike"`
}

const (
	DefaultMetricPort uint   = 2112
	DefaultMetricPath string = "/metrics"
)

type MetricEndpointConfig struct {
	Port uint   `json:"port" yaml:"port"`
	Path string `json:"path" yaml:"path"`
}

type RegisterDeviceRequest struct {
	DeviceRegistrationTokenID string `json:"deviceRegistrationTokenId" validate:"id"`
}

type RegisterDeviceResponse struct {
	DeviceID             string `json:"deviceId"`
	DeviceAccessKeyValue string `json:"deviceAccessKeyValue"`
}
