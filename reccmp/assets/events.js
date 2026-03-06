// reccmp-pack-begin

class ReccmpRegisterEvent extends CustomEvent {
  constructor(callback) {
    super('reccmp-register', { bubbles: true, detail: callback });
  }
}

// reccmp-pack-end

export { ReccmpRegisterEvent };
