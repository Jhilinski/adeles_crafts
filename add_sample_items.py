from app import app, db, Item
import os

# Sample items to add
sample_items = [
    {
        "name": "Beaded Bracelet",
        "description": "A vibrant handmade bracelet with colorful glass beads, perfect for casual or formal wear.",
        "price": 19.99,
        "category": "Beaded Jewelry",
        "image_path": "beaded_bracelet.jpg"  # Ensure this file exists in static/uploads/
    },
    {
        "name": "Plastic Canvas Tissue Box Holder",
        "description": "A beautifully crafted tissue box holder made with plastic canvas, featuring a floral design.",
        "price": 24.99,
        "category": "Plastic Canvas",
        "image_path": "tissue_box_holder.jpg"  # Ensure this file exists
    },
    {
        "name": "Diamond Painted Keychain",
        "description": "A sparkling keychain created with diamond painting techniques, showcasing a heart motif. For display only.",
        "price": 0.00,  # Price 0 indicates display only
        "category": "Diamond Painting",
        "image_path": "diamond_keychain.jpg"  # Ensure this file exists
    },
    {
        "name": "Beaded Necklace",
        "description": "An elegant handmade necklace with intricate beadwork, ideal for special occasions.",
        "price": 34.99,
        "category": "Beaded Jewelry",
        "image_path": "beaded_necklace.jpg"  # Ensure this file exists
    },
    {
        "name": "Religious Plastic Canvas Bookmark",
        "description": "A durable bookmark with a cross design, crafted from plastic canvas for spiritual readers.",
        "price": 9.99,
        "category": "Plastic Canvas",
        "image_path": "religious_bookmark.jpg"  # Ensure this file exists
    }
]

def add_sample_items():
    with app.app_context():
        for item_data in sample_items:
            # Check if item already exists to avoid duplicates
            if not Item.query.filter_by(name=item_data["name"]).first():
                new_item = Item(
                    name=item_data["name"],
                    description=item_data["description"],
                    price=item_data["price"],
                    category=item_data["category"],
                    image_path=item_data["image_path"]
                )
                db.session.add(new_item)
        db.session.commit()
        print("Sample items added successfully!")

if __name__ == "__main__":
    add_sample_items()