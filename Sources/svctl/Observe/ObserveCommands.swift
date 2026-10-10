import ArgumentParser

enum ObserveCommands {
    static let all: [any ParsableCommand.Type] = [
        StatusCommand.self, DoctorCommand.self, PsCommand.self, SessionsCommand.self, KillCommand.self,
        ThrottleCommand.self, NetCommand.self, ViolationsCommand.self,
        ActivityCommand.self,
    ]
}
